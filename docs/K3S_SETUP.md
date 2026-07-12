# K3s On-Prem Server Setup

This document covers deploying the AI SOC core pipeline (Kafka, Redis, Postgres,
ChromaDB, API, orchestrator, Wazuh bridge) to a single on-premise machine running
K3s, as an alternative to the desktop Electron app for teams that want an
unattended, always-on shared instance. Wazuh SIEM, Shuffle SOAR, monitoring, and
vLLM continue to run via their existing Docker Compose files on the same machine —
see `DEPLOYMENT.md`. Nothing in this document touches the desktop app.

## Prerequisites

- A dedicated on-prem machine meeting `DEPLOYMENT.md`'s minimum spec (32 GB RAM, 8
  cores, 100 GB NVMe)
- Docker already installed (for the Wazuh/Shuffle/monitoring/vLLM stacks)
- `git` and Python 3 installed (the Linux secrets-setup script shells out to
  `python3 -c "import secrets; ..."`, matching `DEPLOYMENT.md`'s existing pattern;
  the PowerShell twin for Windows workstations has no Python dependency)
- The Wazuh API and indexer credentials for your Wazuh install (the setup script
  prompts for them — the bridge cannot ingest alerts without them)

## 1. Install K3s

```bash
curl -sfL https://get.k3s.io | sh -
```

K3s installs as a systemd service and ships `kubectl` (as `k3s kubectl`), a
built-in `local-path` StorageClass, and a built-in ServiceLB (Klipper) load
balancer — everything this deployment needs, no extra components.

Symlink so plain `kubectl` works (the manifests and scripts in this repo assume
`kubectl` is on PATH):

```bash
sudo ln -s /usr/local/bin/k3s /usr/local/bin/kubectl
```

Verify:

```bash
sudo kubectl get nodes
# Expected: one node, STATUS Ready
```

Do not pass `--disable servicelb` when installing — the `ai-soc-api` Service
relies on it to bind port 8080 on the host.

## 2. Register the self-hosted GitHub Actions runner

`release.yml`'s `deploy-k3s` job targets `runs-on: [self-hosted, k3s]`. Register
this machine as a runner with that label:

1. In the GitHub repo: Settings → Actions → Runners → New self-hosted runner
2. Follow GitHub's generated `config.sh` command, and when prompted for labels,
   add `k3s` in addition to the defaults
3. Install as a service so it survives reboots: `sudo ./svc.sh install && sudo ./svc.sh start`
4. Verify the runner shows "Idle" in Settings → Actions → Runners

### 2.1 One-time: production approval gate

`release.yml`'s `deploy-production` job pauses on the **production** GitHub
Environment. To make that pause a real approval gate (it is a no-op without
this): repo Settings → Environments → `production` → **Required reviewers** →
add the people allowed to approve production deploys. This is repository
configuration, not code — it cannot be committed, so treat this step as
mandatory setup.

## 3. Bootstrap secrets and site config

Clone the repo onto this machine, then run the setup script once:

```bash
cd ai-soc
./scripts/k8s-setup-secrets.sh
```

(From a Windows workstation with kubectl configured against the cluster, use
`scripts/k8s-setup-secrets.ps1` instead.)

The script prompts for:

- **This machine's LAN IP** — used by in-cluster pods to reach the Wazuh Manager,
  vLLM, and Shuffle running on the same host via Docker Compose
- **Wazuh API user + password** — the bridge authenticates against the Wazuh
  Manager REST API (port 55000) with these
- **Wazuh indexer user + password** — fallback path querying the OpenSearch
  indexer (port 9200) directly; defaults to admin / the API password

It creates an independent `ai-soc-secrets` Secret and `ai-soc-site-config`
ConfigMap in **both** the `ai-soc` (production) and `ai-soc-staging`
namespaces — staging gets its own randomly generated credentials.
**Save the admin passwords it prints (one per namespace) — they are not
stored anywhere else.**

Re-running the script is safe: if `ai-soc-secrets` already exists it is left
untouched (rotating it would break Postgres/Redis auth against data the PVCs
were initialised with), and only the site config is re-applied. To rotate
credentials deliberately, delete the Secret first — and be aware that Postgres
retains the password its data directory was initialised with, so a rotation
also requires an `ALTER USER` inside Postgres or wiping the `pg-data` PVC.

## 4. Start the Docker-Compose-managed services

Wazuh, Shuffle, monitoring, and vLLM are not part of the K3s manifests — start
them exactly as documented in `DEPLOYMENT.md`'s "Option B — Docker Compose"
section, on this same machine.

## 5. First deploy

Normally deployment happens automatically on the next tagged release:
`release.yml` first deploys to the `ai-soc-staging` namespace and verifies it
end-to-end with a synthetic alert (staging API listens on port **8081**), then
waits for a human to approve the **production** environment in the Actions UI,
and only then applies the production overlay and updates all three app
Deployments. After a successful promotion, staging is scaled to zero to return
its resources; its PVCs persist and the next release's staging deploy restores
it. To bootstrap production manually before the first release:

```bash
kubectl apply -k k8s/overlays/production
kubectl get pods -n ai-soc -w
```

Expected: `kafka-0`, `redis-0`, `postgres-0`, `chromadb-0` reach `Running`/`Ready`,
then `ai-soc-api`, `ai-soc-orchestrator`, `ai-soc-wazuh-bridge` reach
`Running`/`Ready`.

## 6. Post-install verification

```bash
# API reachable on the host, port 8080:
curl http://localhost:8080/health
# Expected: {"status":"ok","service":"ai_soc_pipeline"}

# Wazuh bridge is authenticating against the host's Wazuh Manager:
kubectl logs -n ai-soc deployment/ai-soc-wazuh-bridge --tail=50
```

**Read the bridge logs carefully.** Wrong Wazuh credentials do NOT crash the
pod — the bridge's poll loop swallows auth failures and retries forever, so the
pod will show `Running` while ingesting nothing. The underlying HTTP status
usually is not printed directly: repeated `Bridge polling error` lines starting
immediately after startup almost always mean bad Wazuh credentials. A healthy
bridge shows periodic alert fetches with no repeating errors. (If Wazuh itself
is not running yet, start it per section 4 first — a connection-refused error
here means Wazuh is down, not that the credentials are wrong.)

```bash
# Orchestrator is consuming from Kafka:
kubectl logs -n ai-soc deployment/ai-soc-orchestrator --tail=50
# Expected: consumer loop running, no crash loop

# End-to-end: generate a synthetic alert and confirm it's processed.
# Kafka is only reachable inside the cluster, so run the generator from the
# API pod (it has the right image and environment):
kubectl exec -n ai-soc deployment/ai-soc-api -- \
  python -m scripts.synthetic_log_generator --eps 1 --duration 10
```

Then check `http://localhost:8080/api/activity` shows the new alert within ~30s.

If any pod is stuck in `CrashLoopBackOff`, check `kubectl describe pod -n ai-soc
<pod-name>` and `kubectl logs -n ai-soc <pod-name> --previous`.

## 7. Known limitations of the K3s deployment

- **GeoIP enrichment is degraded.** The container image does not include the
  GeoLite2 database (`MAXMIND_DB_PATH` defaults to `./data/GeoLite2-City.mmdb`,
  which is excluded from the image), and no volume mounts one. Alerts are still
  processed normally, but geo-context fields (country/city/coordinates) come
  back as an error object instead of data. Follow-up: mount the `.mmdb` via a
  hostPath or PVC if geo-enrichment matters to your analysts.
- **SOAR is disabled by default.** `SOAR_ENABLED=false` in `k8s/configmap.yaml`,
  and the Secret's `SHUFFLE_API_KEY` is a dummy value. If you enable SOAR, also
  replace `SHUFFLE_API_KEY` with a real key from your Shuffle instance.
- **Pod security hardening is pending.** The StatefulSets/Deployments do not yet
  set `securityContext`/`fsGroup`; the current images handle their own privilege
  dropping, but hardened/distroless image swaps will need this added.
- **Staging shares the host's Wazuh but does not poll it.** The staging
  namespace runs the full pipeline minus the wazuh-bridge; release verification
  uses synthetic alerts. If you need staging to process real alerts ad-hoc,
  its secrets already contain the Wazuh credentials — deploy the bridge into
  `ai-soc-staging` manually from `k8s/base/app/wazuh-bridge-deployment.yaml`.
