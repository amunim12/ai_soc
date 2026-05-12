# Contributing to AI SOC

## Air-gap and security context

This repository is deployed in **air-gapped, classified-adjacent security environments**. Every contribution — however small — must satisfy the security and operational requirements below before it reaches any deployment. There are no exceptions.

---

## Table of Contents

- [Who can contribute](#who-can-contribute)
- [Development environment requirements](#development-environment-requirements)
- [Code transfer policy](#code-transfer-policy)
- [Branching strategy](#branching-strategy)
- [Commit standards](#commit-standards)
- [Code review process](#code-review-process)
- [Security review requirements](#security-review-requirements)
- [Testing requirements](#testing-requirements)
- [Dependency policy](#dependency-policy)
- [Prohibited practices](#prohibited-practices)
- [Reporting vulnerabilities](#reporting-vulnerabilities)

---

## Who can contribute

Contributions are accepted **only from authorised team members** on approved development machines. External contributions via public pull requests are not accepted. If you are not part of the authorised team and believe you have found a security issue, follow the [vulnerability reporting process](SECURITY.md#reporting-a-vulnerability) in `SECURITY.md`.

---

## Development environment requirements

Before writing any code:

1. **Use an approved, hardened workstation.** The machine must be enrolled in the organisation's endpoint management system and have full-disk encryption enabled.

2. **Isolate the development environment.** Development machines must not be simultaneously connected to untrusted networks. Use a dedicated VM or separate physical machine for network-connected dependency fetching; keep the actual development and build environment offline.

3. **Use the project virtualenv.** Never use a system-wide Python installation for development work.

   ```bash
   python -m venv backend/.venv
   source backend/.venv/bin/activate
   pip install -r backend/requirements.txt
   ```

4. **Sign your commits.** Configure GPG commit signing before making any commits:

   ```bash
   git config user.signingkey <YOUR_GPG_KEY_ID>
   git config commit.gpgsign true
   ```

5. **Do not store credentials in the repository.** Use `backend/.env` (git-ignored) for all secrets. Run `git secrets --scan` before every push if git-secrets is available.

---

## Code transfer policy

Because deployments are air-gapped, all code transfers to and from isolated networks must follow the organisation's approved media control policy:

- Use only approved, scanned, write-protected removable media.
- Log every transfer with timestamp, hash (SHA-256), source, and destination.
- Do not transfer code via personal email, cloud storage, or consumer messaging applications.
- After transfer, verify the SHA-256 hash of every file against the value computed on the source machine.

---

## Branching strategy

```
main          ← stable, deployable, protected — direct push forbidden
  └─ develop  ← integration branch
       └─ feature/<short-description>   ← new features
       └─ fix/<short-description>       ← bug fixes
       └─ security/<short-description>  ← security fixes (restricted visibility)
```

- `main` requires two approvals and a passing test suite before merge.
- `security/*` branches have restricted visibility — notify the security lead before creating one.
- Branch names must be lowercase, hyphen-separated, and descriptive.

---

## Commit standards

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short summary>

[optional body — explain WHY, not what]

[optional footer: breaking change notice or issue reference]
```

**Types:** `feat`, `fix`, `security`, `refactor`, `test`, `docs`, `chore`, `perf`

**Examples:**

```
feat(hitl): replace polling loop with pg_notify for zero-latency decisions

security(auth): enforce minimum 64-byte JWT secret at startup

fix(kafka): correct lz4 compression fallback for confluent-kafka 2.6+
```

- Keep the subject line under 72 characters.
- Write in the imperative mood ("add", "fix", "remove" — not "added", "fixes").
- Reference internal ticket numbers in the footer where applicable.

---

## Code review process

1. Open a pull request from your feature branch into `develop`.
2. Assign at least **one domain reviewer** (someone familiar with the changed subsystem).
3. For any change touching `agents/`, `infrastructure/`, `api/auth_api.py`, or `orchestration/`, assign the **security lead** as a required reviewer.
4. All automated checks (lint, type-check, tests) must pass before review begins.
5. Address every review comment before requesting re-review; do not dismiss reviews unilaterally.
6. Squash-merge into `develop`; fast-forward merge into `main` after a release review.

---

## Security review requirements

The following change categories require an explicit security sign-off before merge, in addition to the standard code review:

| Change category | Reason |
|---|---|
| New external API integration | Attack surface expansion, data exfiltration risk |
| Authentication or authorisation changes | Risk of privilege escalation or bypass |
| New environment variable / secret | Must be documented in `.env.example`, never hard-coded |
| Dependency additions or version bumps | Supply chain risk — see dependency policy |
| Dockerfile or docker-compose changes | Container escape and network isolation concerns |
| Any change to the HITL decision path | Integrity of human oversight must be preserved |
| Kafka topic or consumer group changes | Alert delivery guarantees and audit trail integrity |
| LLM prompt changes | Prompt injection surface |

The security reviewer must confirm:

- No credentials, API keys, or internal hostnames are present in code or comments.
- No new outbound network calls are introduced that would break air-gap operation.
- No use of dynamic code execution (`eval`, `exec`) or shell injection vectors on unsanitised input.
- Input from external sources (Wazuh events, analyst submissions, uploaded documents) is validated before use.
- TLS certificate verification is not disabled on any HTTP client call.

---

## Testing requirements

All pull requests must include or update tests. The test suite must pass completely before merge.

```bash
cd backend
pytest tests/ -v --tb=short
```

### Coverage expectations

| Module | Minimum line coverage |
|---|---|
| `agents/` | 80% |
| `api/` | 70% |
| `infrastructure/` | 70% |
| `orchestration/` | 80% |
| `schemas/` | 90% |

### Test environment rules

- Tests must not make real network calls. Use `fakeredis`, mock Kafka, and mock HTTP clients.
- Tests must not read from or write to production databases or the live SQLite file.
- Tests must be deterministic and must not rely on wall-clock time or random seeds unless explicitly controlled.
- Do not commit tests that assert unconditionally or that are permanently skipped without a dated justification comment.

---

## Dependency policy

Adding or upgrading dependencies requires the security lead's approval.

**Adding a new dependency:**

1. Confirm there is no existing dependency that provides equivalent functionality.
2. Check the package on [OSV](https://osv.dev) and the NVD for known vulnerabilities.
3. Pin the version exactly in `requirements.txt` (e.g., `requests==2.32.3`, not `requests>=2`).
4. Download the wheel and its transitive dependencies into `vendor/python/` for offline installation.
5. Document the purpose of the dependency in the PR description.

**Upgrading a dependency:**

1. Read the changelog for security-relevant changes.
2. Run the full test suite after upgrading.
3. Update `vendor/python/` with the new wheel.

**Prohibited dependency sources:**

- Packages not available on PyPI or a trusted internal mirror.
- Any package that makes outbound network calls at import time.
- Git-based `pip install git+...` references.

---

## Prohibited practices

The following are prohibited and will cause a PR to be rejected:

| Practice | Risk |
|---|---|
| Hard-coded credentials, API keys, or tokens anywhere in the codebase | Secret exposure in git history |
| Using `print()` for logging — use the `logging` module | Log level bypass, uncontrolled output |
| Disabling TLS certificate verification (`verify=False`) | MITM attacks |
| Dynamic code execution on unsanitised external input | Remote code execution |
| Shell injection via unsanitised arguments to subprocess calls | Command injection |
| Logging full alert payloads or analyst notes at `DEBUG` level in production | Sensitive data leakage |
| Committing `.env`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, or database files | Credential exposure |
| Bypassing pre-commit hooks with `--no-verify` | Circumventing security controls |
| Using `TODO: fix security` as a substitute for fixing the issue | Deferred risk becoming a shipped vulnerability |

---

## Reporting vulnerabilities

Do not open a public issue for security vulnerabilities. Follow the coordinated disclosure process in [SECURITY.md](SECURITY.md).
