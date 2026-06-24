# Security Policy

## Overview

AI SOC processes live security events, analyst decisions, and threat intelligence data. A compromise of this system could allow an attacker to suppress alerts, manipulate playbooks, exfiltrate incident data, or pivot into monitored infrastructure. This policy defines the security requirements and expectations for all deployments.

---

## Table of Contents

- [Supported Versions](#supported-versions)
- [Air-Gap requirements](#air-gap-requirements)
- [Network isolation architecture](#network-isolation-architecture)
- [Credential and secret management](#credential-and-secret-management)
- [Authentication and access control](#authentication-and-access-control)
- [Data classification and handling](#data-classification-and-handling)
- [Container and infrastructure hardening](#container-and-infrastructure-hardening)
- [LLM and AI security](#llm-and-ai-security)
- [Audit and logging requirements](#audit-and-logging-requirements)
- [Dependency and supply chain security](#dependency-and-supply-chain-security)
- [Incident response](#incident-response)
- [Reporting a vulnerability](#reporting-a-vulnerability)

---

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Deployments running older commits must upgrade before requesting security support.

---

## Air-Gap requirements

This system is designed and tested for **fully air-gapped deployment**. The following requirements are mandatory in all production environments.

### Hard requirements

- **No inbound or outbound internet connectivity** on any host running pipeline components. Firewall rules must deny all traffic to/from external IP ranges at the network level, not just the host firewall.
- **No cloud telemetry.** Set `LOCAL_AI_ONLY=true` in `.env`. All LLM inference must use the locally hosted model endpoint (`LOCAL_LLM_BASE_URL`). Never configure `OPENAI_API_KEY` or any third-party LLM endpoint in production.
- **No cloud-hosted vector storage.** ChromaDB must run from the local Docker container defined in `backend/docker-compose.yml`.
- **All embedding models must be pre-downloaded.** The `sentence-transformers` model (`all-MiniLM-L6-v2`) must be present in the local model cache before the system starts. It must never be fetched at runtime.
- **TI APIs must be local.** VirusTotal, OTX, and Shodan are disabled by default (`USE_MOCK_TI=true`). If threat intelligence is required, deploy MISP on the isolated network and point `MISP_URL` to the internal instance.

### Pre-deployment checklist

Before final network isolation:

- [ ] All Docker images pulled and verified (`docker image ls`)
- [ ] Python wheels vendored to `vendor/python/`
- [ ] Embedding models downloaded and cached
- [ ] LLM weights loaded and accessible at `LOCAL_LLM_BASE_URL`
- [ ] MaxMind GeoLite2 database placed at `MAXMIND_DB_PATH`
- [ ] All `.env` values set to internal hostnames/IPs — no public hostnames
- [ ] DNS resolution tested for all internal services without external DNS
- [ ] `USE_MOCK_TI=true` OR `MISP_URL` pointing to internal MISP instance
- [ ] `LOCAL_AI_ONLY=true` confirmed in `.env`

---

## Network isolation architecture

```
┌────────────────────────── AIR-GAPPED ENCLAVE ─────────────────────────────┐
│                                                                             │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────────────┐    │
│  │  Analyst     │    │  SOC Pipeline │    │  Wazuh SIEM Cluster      │    │
│  │  Workstation │───▶│  (FastAPI +   │◀───│  Manager · Indexer ·     │    │
│  │  (Electron)  │    │   LangGraph)  │    │  Dashboard               │    │
│  └──────────────┘    └──────┬────────┘    └──────────────────────────┘    │
│                             │                                              │
│                    ┌────────┴──────────┐                                  │
│                    │  Infrastructure   │                                   │
│                    │  Kafka · Redis    │                                   │
│                    │  Postgres · Chroma│                                   │
│                    └───────────────────┘                                   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Monitored endpoints / agents (Wazuh agents installed)               │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Network firewall: DENY ALL traffic to/from internet                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

**No component in the diagram above should have a route to the internet in production.**

---

## Credential and secret management

### Rules

1. **No credentials in source control.** `.env` is git-ignored. `.env.example` must contain only placeholder values — never real keys.

2. **JWT secret key.** Must be a cryptographically random string of at least 64 bytes. Generate one with:

   ```bash
   python -c "import secrets; print(secrets.token_hex(64))"
   ```

   The value `change-me-in-production-use-strong-random-secret` (the default) must never be used in any environment beyond local development on a non-networked machine.

3. **Database passwords.** The default PostgreSQL password `soc_pipeline_dev` must be changed before any deployment that handles real security events. Use a password manager or secrets vault to store and rotate database credentials.

4. **API keys.** Threat intelligence API keys (VirusTotal, OTX, Shodan, MISP) must be stored only in `.env`. They must never appear in log output, API responses, or error messages.

5. **Shuffle API key.** Stored in both `deploy/shuffle/.env` and `backend/.env`. These must be identical and must be regenerated during initial Shuffle setup. The key grants full SOAR automation authority — treat it with the same sensitivity as a root credential.

6. **Wazuh API credentials.** The Wazuh manager API user has the ability to read all security events. Use a dedicated, least-privilege API user and rotate the password on the same schedule as your other privileged credentials.

7. **Rotation schedule.** All credentials must be rotated at least every 90 days, or immediately after any suspected compromise.

### Secret scanning

Run the following before every commit:

```bash
# Using git-secrets (install once: git secrets --install)
git secrets --scan

# Or using trufflehog for deeper history scanning
trufflehog git file://. --only-verified
```

---

## Authentication and access control

### API authentication

All API endpoints (except `GET /health`) require a valid JWT Bearer token. Tokens are issued at `POST /api/auth/login` and expire after 8 hours (`JWT_EXPIRE_MINUTES=480`).

Reduce `JWT_EXPIRE_MINUTES` to 60 or less in high-security environments and implement token refresh.

### Roles

| Role | Capabilities |
|---|---|
| `analyst` | View alerts, HITL queue, SIEM/SOAR dashboards; submit HITL decisions |
| `admin` | All analyst capabilities + user management + auth audit log |

Principle of least privilege: create analyst accounts for day-to-day SOC operations and reserve admin accounts for system administration only.

### HITL decision integrity

The Human-in-the-Loop path is the critical safety control in this system. The following properties must be preserved:

- Every HITL decision is recorded in `hitl_decisions` with `analyst_id`, `decided_at`, and the full `final_playbook_json`.
- The pipeline never executes a high-confidence or CRITICAL-severity playbook without either a human approval or an explicit timeout escalation.
- HITL decisions are immutable once written — the `store_decision()` path must not allow updates to an existing decision.
- The `pg_notify` path must only fire after the decision row is committed, not before.

### Session management

- JWT tokens are not revocable in the default implementation. For environments requiring immediate revocation (e.g., after analyst account compromise), implement a token blocklist backed by Redis with TTL equal to `JWT_EXPIRE_MINUTES`.
- Do not store JWT tokens in localStorage in web deployments. The Electron desktop client stores them in memory only.

---

## Data classification and handling

Security events processed by this pipeline must be treated as **sensitive operational data**:

| Data type | Classification | Retention |
|---|---|---|
| Raw Wazuh alerts | Sensitive | Per organisational policy |
| HITL reviews and decisions | Sensitive | 90 days minimum for audit |
| Audit log | Sensitive | 1 year minimum |
| LLM-generated playbooks | Internal | Same as source alert |
| Analyst notes in HITL decisions | Sensitive | Same as HITL reviews |
| Threat intelligence results | Internal | Purge from Redis after 24h (default) |

### Data at rest

- The PostgreSQL database and SQLite file at `backend/data/hitl.db` contain alert content and analyst decisions. These volumes must be on encrypted storage.
- The ChromaDB volume (`chroma_data`) contains embeddings derived from incident data and knowledge base documents. Encrypt the volume.
- Redis persistence (`redis_data`) may contain cached alert deduplication keys and TI results. Encrypt the volume and enable Redis AUTH.

### Data in transit

- All communication between the Electron UI and the FastAPI backend must use HTTPS in production. The default development configuration uses plain HTTP over localhost only.
- Kafka is configured with PLAINTEXT transport in the default `docker-compose.yml`. For production, configure Kafka with TLS (`SASL_SSL`) and ACLs per topic.
- The Wazuh API client validates TLS certificates. Do not override certificate verification.

---

## Container and infrastructure hardening

### Docker

- All containers run as non-root users where possible. Verify with `docker inspect --format='{{.Config.User}}' <container>`.
- Remove the `privileged: true` flag from any container that does not strictly require it.
- Orborus (Shuffle worker orchestrator) mounts the Docker socket (`/var/run/docker.sock`) — this grants container-level root on the host. Restrict Orborus to a dedicated host or VM isolated from the pipeline host.
- Do not expose infrastructure ports (Kafka 9092, Redis 6379, PostgreSQL 5432, ChromaDB 8888) to any network interface other than `127.0.0.1` or the internal Docker bridge network.

### Kafka

- Disable auto-topic creation (`KAFKA_AUTO_CREATE_TOPICS_ENABLE=false` is already set).
- In production, configure Kafka ACLs to restrict which services can produce to or consume from each topic.
- Do not reduce the default retention period (7 days) for `wazuh.audit` — this is the pipeline's primary audit trail.

### Redis

- Enable Redis AUTH in production: set `requirepass <strong-password>` in the Redis configuration and update `REDIS_URL` to `redis://:<password>@localhost:6379/0`.
- Disable Redis commands that allow data deletion or configuration changes from unauthenticated clients (`rename-command FLUSHALL ""`, `rename-command CONFIG ""`).

### PostgreSQL

- Change the default password (`soc_pipeline_dev`) before connecting to any network.
- Grant the `soc` application user only the permissions it needs: `SELECT`, `INSERT`, `UPDATE` on `hitl_reviews`, `hitl_decisions`, and `audit_log`. No `DROP`, `CREATE`, or superuser privileges.
- Enable `pg_audit` or the built-in `log_statement = 'mod'` setting to log all write operations.

---

## LLM and AI security

### Prompt injection

The pipeline passes raw alert content from Wazuh into LLM prompts. An attacker who can write to a monitored log source could attempt to inject instructions into the alert payload.

Mitigations already in place:
- Alert content is embedded as user data within a structured prompt, separated from system instructions.
- The LLM output is parsed against a strict Pydantic schema; unexpected output is rejected rather than executed.
- HITL review is required for CRITICAL alerts and low-confidence outputs.

Additional hardening:
- Do not include analyst credentials, internal IP ranges, or playbook execution tokens in LLM context.
- Monitor LLM outputs for anomalous playbook content before execution (e.g., playbook steps referencing external URLs or attempting to disable security controls).

### Model integrity

- Store LLM weights on encrypted storage.
- Verify the SHA-256 hash of model weight files against the published hash before first use and after any transfer.
- Do not use model checkpoints from untrusted sources.

### Embedding model

- The `all-MiniLM-L6-v2` embedding model is downloaded from HuggingFace before air-gapping. Verify its integrity:

  ```bash
  python -c "
  from sentence_transformers import SentenceTransformer
  m = SentenceTransformer('all-MiniLM-L6-v2')
  print('Model loaded successfully')
  "
  ```

---

## Audit and logging requirements

The following events must always be logged at `INFO` level or above and must never be suppressed:

| Event | Log destination |
|---|---|
| Alert received and processed | SQLite / PostgreSQL audit_log |
| HITL review created | PostgreSQL hitl_reviews |
| HITL decision submitted | PostgreSQL hitl_decisions |
| Playbook executed via SOAR | SQLite audit_log + Kafka wazuh.audit |
| Alert dropped or escalated | SQLite audit_log + Kafka wazuh.audit |
| API authentication (success and failure) | SQLite auth_audit_log |
| User account creation or deletion | SQLite auth_audit_log |

Do not log the following at any level:

- Plaintext passwords or tokens
- Full JWT payloads
- SMTP passwords or third-party API keys
- Raw LLM prompt content when it contains alert data (log a hash or truncated summary instead)

---

## Dependency and supply chain security

- All Python dependencies are pinned to exact versions in `requirements.txt`.
- Before deploying a new version, compare `requirements.txt` against the previous version and review every changed package on OSV and the NVD.
- Pre-download all wheels into `vendor/python/` and use `pip install --no-index --find-links=vendor/python/ -r requirements.txt` for installation on air-gapped hosts.
- Node.js dependencies are locked via `package-lock.json`. Do not run `npm install` with `--legacy-peer-deps` or flags that bypass the lockfile.
- Docker images are pinned to specific digest tags in production rather than `:latest` tags where possible.

---

## Incident response

If you suspect this system has been compromised:

1. **Isolate immediately.** Disconnect the host from all networks, including the internal network.
2. **Preserve state.** Take memory and disk snapshots before shutting down services.
3. **Stop the pipeline.** `docker compose -f backend/docker-compose.yml down` — this prevents further automated actions.
4. **Revoke credentials.** Rotate all secrets listed in the `.env` file. Regenerate the JWT secret key, database passwords, and all API keys.
5. **Review audit logs.** Check `hitl_decisions`, `audit_log`, and `auth_audit_log` for signs of unauthorised decisions, playbook manipulation, or privilege escalation.
6. **Notify stakeholders.** Follow the organisation's incident response plan.
7. **Do not redeploy** from the same host until forensic analysis is complete.

---

## Reporting a vulnerability

**Do not create a public GitHub issue for security vulnerabilities.**

Responsible disclosure process:

1. Prepare a written report including:
   - A description of the vulnerability and affected component
   - Steps to reproduce
   - Potential impact (what an attacker could achieve)
   - Any suggested mitigations

2. Send the report to the project maintainer via an encrypted channel. If no secure channel has been established, contact the university supervisor or department security officer directly.

3. Allow a minimum of **14 days** for acknowledgement and **90 days** for remediation before public disclosure. We will acknowledge receipt within 72 hours.

4. After remediation is deployed, coordinate on the timing and content of any public disclosure.

We do not operate a bug bounty programme. We will credit researchers who responsibly disclose vulnerabilities in any public acknowledgement, if they consent to being named.
