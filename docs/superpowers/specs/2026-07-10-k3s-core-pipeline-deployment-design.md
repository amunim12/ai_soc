# On-Prem K3s Deployment for the AI SOC Core Pipeline

**Status:** Approved
**Date:** 2026-07-10

## Problem

`release.yml` Stage 5 (`deploy-k3s`) runs `kubectl set image deployment/ai-soc-api ...` and `kubectl rollout status`, but no Kubernetes manifests exist anywhere in the repo, and no self-hosted K3s runner is documented or provisioned. The job has nothing to deploy to. This spec defines the manifests, secrets/storage strategy, and bootstrap process needed to close that gap.

## Goal

Provide a real, working K3s deployment path for the AI SOC core pipeline on a single on-premise machine, as an **unattended server install** — separate from and independent of the existing Electron desktop app (which continues to manage its own local Docker Compose stack, untouched).

## Scope

**In scope — becomes K8s-managed, in a new `ai-soc` namespace:**

| Component | Kind | Why |
|---|---|---|
| Kafka | StatefulSet | alert ingestion bus |
| Redis | StatefulSet | dedup + caching |
| PostgreSQL | StatefulSet | HITL audit log |
| ChromaDB | StatefulSet | vector store (RAG) |
| `ai-soc-api` | Deployment | FastAPI HTTP server (dashboard, HITL, auth) |
| `ai-soc-orchestrator` | Deployment | Kafka consumer running the LangGraph agent pipeline — the actual alert processing |
| `ai-soc-wazuh-bridge` | Deployment | pulls Wazuh alerts, pushes them into Kafka |

The orchestrator and wazuh-bridge are currently **not containerized at all** — they run as bare `python -m ...` processes per `docs/STARTUP_COMMANDS.md`. Bringing them in as Deployments (built from the same image as `Dockerfile.api`, different container `command`) is required for the pipeline to process anything end-to-end under K3s; without them, alerts would reach Kafka but never get analyzed.

**Out of scope — stays on Docker Compose, same physical machine:**

- Wazuh SIEM (`wazuh-docker/single-node/docker-compose.yml`) — multi-container system with its own cert-bootstrap; migrating it is a separate project
- Shuffle SOAR (`deploy/shuffle/docker-compose.yml`)
- Prometheus + Grafana (`monitoring/docker-compose.monitoring.yml`)
- vLLM (`docker run --gpus all ...`) — GPU scheduling stays out of this pass

K3s and Docker Compose coexist on the same on-prem box — two process managers on one host, no cloud involved anywhere. This mirrors how `DEPLOYMENT.md` already runs these as independent stacks talking over localhost/LAN ports.

## Architecture

```
┌─────────────────────────── single on-prem machine ───────────────────────────┐
│                                                                                 │
│  ┌──────────── K3s (namespace: ai-soc) ────────────┐   ┌── Docker Compose ──┐ │
│  │                                                    │   │                    │ │
│  │  StatefulSets: kafka, redis, postgres, chromadb   │   │  Wazuh SIEM        │ │
│  │       (ClusterIP only — no external exposure)     │   │  Shuffle SOAR      │ │
│  │                                                    │   │  Prometheus/Grafana│ │
│  │  Deployments: api, orchestrator, wazuh-bridge     │◄──┼──vLLM (docker run) │ │
│  │       api ──NodePort:8080──────────────┐          │   │                    │ │
│  │       wazuh-bridge ──► host LAN IP ─────┼──────────►  Wazuh Manager:55000 │ │
│  │                                          │          │                    │ │
│  └──────────────────────────────────────────┼──────────┘                    │ │
│                                              │                                │ │
└──────────────────────────────────────────────┼────────────────────────────────┘
                                                 ▼
                                    Shuffle webhooks, analyst browsers
```

Key cross-boundary links — all in-cluster pods reaching host-based services follow the same pattern: the node's own LAN IP, since on bare-metal K3s (not k3d/Docker Desktop) the node *is* the host — plain Linux networking, no VM tunnel needed. None of these are hardcoded; each is a `ConfigMap`/`Secret` env var pointing at the host's LAN IP + the port already listed in `DEPLOYMENT.md`'s port-reference table:

| Caller (in-cluster) | Target (Docker Compose, same host) | Env var |
|---|---|---|
| `wazuh-bridge` | Wazuh Manager REST API, port 55000 | `WAZUH_MANAGER_HOST` |
| `orchestrator` | vLLM inference server, port 8001 | `LOCAL_LLM_BASE_URL` |
| `orchestrator` | Shuffle SOAR (playbook execution), if `SOAR_ENABLED=true` | `SHUFFLE_BASE_URL` |

And the reverse direction:
- `api` (in-cluster) ← Shuffle webhooks + analyst browsers (host/LAN): reached via `NodePort` on 8080, matching the existing port-reference table in `DEPLOYMENT.md`.
- Kafka/Redis/Postgres/ChromaDB: `ClusterIP` only — nothing outside the cluster needs them directly now that orchestrator and wazuh-bridge are in-cluster too.

## Manifest tooling

Raw Kubernetes YAML, no Helm/Kustomize. `release.yml` already drives `kubectl` directly; a templating layer would add machinery for zero benefit on a single known on-prem target. Revisit only if this ever needs to ship to multiple differently-sized customer sites.

## Directory layout

```
k8s/
  namespace.yaml
  configmap.yaml                    # non-secret env vars (ports, feature flags)
  secret.example.yaml               # template only — real values never committed
  infra/
    kafka-statefulset.yaml
    kafka-service.yaml               # ClusterIP
    redis-statefulset.yaml
    redis-service.yaml                # ClusterIP
    postgres-statefulset.yaml
    postgres-service.yaml            # ClusterIP
    chromadb-statefulset.yaml
    chromadb-service.yaml            # ClusterIP
  app/
    api-deployment.yaml
    api-service.yaml                 # NodePort 8080
    orchestrator-deployment.yaml
    wazuh-bridge-deployment.yaml
```

## Secrets

Not committed to git (air-gapped/on-prem, no cloud KMS available). A setup script (`scripts/k8s-setup-secrets.sh` + `.ps1` twin, matching the existing `backup.sh`/`backup.ps1` pattern) generates random values the same way `DEPLOYMENT.md` already documents (`python3 -c "import secrets; print(secrets.token_hex(...))"`) and creates the secret imperatively:

```bash
kubectl create secret generic ai-soc-secrets -n ai-soc \
  --from-literal=JWT_SECRET_KEY=... \
  --from-literal=POSTGRES_PASSWORD=... \
  --from-literal=REDIS_PASSWORD=...
```

`secret.example.yaml` in the repo documents the expected keys without real values, mirroring `backend/.env.example`.

## Storage

K3s's built-in `local-path` StorageClass (dynamic provisioning via hostPath, no NFS/cloud storage, zero extra install). One PVC per stateful component — `kafka-data`, `redis-data`, `chroma-data`, `pg-data` — matching today's docker-compose named volumes 1:1, so backup/restore semantics carry over conceptually (though `scripts/backup.sh` will need a K8s-aware variant in a follow-up, out of scope here).

## Health checks

- `api`: liveness + readiness probes against the existing `/health` endpoint.
- `orchestrator` / `wazuh-bridge`: no HTTP surface (they're consumer loops), so no custom probe — rely on K8s's default crash-restart behavior (`restartPolicy: Always`).

## Resource requests/limits

Conservative defaults sized against `DEPLOYMENT.md`'s stated minimum host spec (32 GB RAM / 8 cores), leaving headroom for the Docker-Compose-managed Wazuh/Shuffle/vLLM processes running on the same box. Exact values tuned during implementation against actual measured usage where possible.

## K3s install + self-hosted runner registration

A new setup doc (extends `DEPLOYMENT.md` or a new `docs/K3S_SETUP.md`) covering:
1. Install K3s on the on-prem machine (`curl -sfL https://get.k3s.io | sh -`)
2. Verify with `kubectl get nodes`
3. Register the machine as a GitHub Actions self-hosted runner with the `k3s` label, matching `runs-on: [self-hosted, k3s]` in `release.yml`
4. Apply `k8s/namespace.yaml` and run the secrets setup script once, manually, before the first CD run

## CD pipeline changes (`release.yml` Stage 5)

Current Stage 5 assumes the Deployment already exists (`kubectl set image` only). Two changes:
1. Add an idempotent `kubectl apply -f k8s/ -n ai-soc` step before `kubectl set image` — creates resources on first run, no-ops on subsequent runs when unchanged, updates non-image fields if the manifests change.
2. Add rollback: if the post-deploy health-check loop fails, run `kubectl rollout undo deployment/ai-soc-api -n ai-soc` (and the other two Deployments) before failing the job, instead of leaving a broken image live.

## Testing / validation plan

- `kubectl apply --dry-run=client -f k8s/` (and `--dry-run=server` against a real cluster) to catch manifest errors before merge.
- Manual smoke test on the on-prem K3s box: apply manifests, confirm all pods reach `Ready`, curl `/health` via the NodePort, confirm `wazuh-bridge` logs show a successful connection to the host's Wazuh Manager, publish a test alert and confirm `orchestrator` consumes and processes it (existing `synthetic_log_generator.py` can drive this).

## Explicitly not doing (follow-up work, not this pass)

- Migrating Wazuh, Shuffle, or monitoring into K8s
- GPU scheduling / vLLM in-cluster
- Ingress/TLS (NodePort is sufficient for one on-prem box)
- Multi-node HA, Helm/Kustomize, staging environment
- K8s-aware backup/restore tooling (existing `scripts/backup.sh` targets Docker volumes only)
