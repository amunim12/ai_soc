# K3s Staging Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every stable release tag deploys to an isolated `ai-soc-staging` namespace first, is verified end-to-end with a synthetic alert, and is promoted to the `ai-soc` production namespace only after a human approves via a GitHub Environment gate.

**Architecture:** The flat `k8s/` manifests restructure into Kustomize base + overlays (`k8s/base/`, `k8s/overlays/production/`, `k8s/overlays/staging/`). The staging overlay renames the namespace, deletes the wazuh-bridge Deployment, halves resources, and moves the API Service to host port 8081. `release.yml`'s single `deploy-k3s` job splits into `deploy-staging` (apply + rollout + health + synthetic-alert e2e) and `deploy-production` (`environment: production` approval gate → apply → smoke test → guarded rollback → scale staging to zero). Image pinning moves from sed-into-manifests to each overlay's `images:` transformer `newTag`, with a rendered-output count assertion. Full design rationale: `docs/superpowers/specs/2026-07-12-k3s-staging-gate-design.md`.

**Tech Stack:** Kustomize (via `kubectl kustomize` / `kubectl apply -k` on the K3s runner; standalone kustomize v5.4.3 pinned in CI), kubeconform v0.8.0, GitHub Actions Environments.

**Environment notes for all tasks:**
- Work from `d:\ai_soc` on branch `feature/k3s-deployment`. Do not switch branches.
- kubeconform is installed at `$HOME/bin/kubeconform.exe` (invoke with that full path — PATH exports don't persist between Bash calls). `kubectl` is available locally via Docker Desktop; use `kubectl kustomize <dir>` for local rendering.
- End every commit message with the trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
- The pre-commit hook prints non-blocking WARNING lines — ignore them.
- The working tree contains unrelated uncommitted user changes (DEPLOYMENT.md, frontend/*, website/*, docs/chapter_*, docs/standee-design-prompt.md). Never stage or modify them.

---

### Task 1: Restructure `k8s/` into `base/` with namespace-agnostic content

**Files:**
- Move: `k8s/configmap.yaml` → `k8s/base/configmap.yaml` (edited)
- Move: `k8s/infra/*.yaml` (8 files) → `k8s/base/infra/` (edited)
- Move: `k8s/app/*.yaml` (4 files) → `k8s/base/app/` (edited)
- Delete: `k8s/namespace.yaml` (namespace objects move to overlays in Tasks 2-3)
- Create: `k8s/base/kustomization.yaml`
- Unchanged in place: `k8s/secret.example.yaml`

- [ ] **Step 1: Move the files with git mv**

```bash
cd d:/ai_soc
mkdir -p k8s/base
git mv k8s/configmap.yaml k8s/base/configmap.yaml
git mv k8s/infra k8s/base/infra
git mv k8s/app k8s/base/app
git rm k8s/namespace.yaml
```

- [ ] **Step 2: Strip `namespace: ai-soc` from every moved manifest**

Each of the 13 files under `k8s/base/` has exactly one `  namespace: ai-soc` line inside `metadata:`. Remove it from every file:

```bash
cd d:/ai_soc
grep -rln "^  namespace: ai-soc$" k8s/base/ | while IFS= read -r f; do
  sed -i "/^  namespace: ai-soc$/d" "$f"
done
grep -rn "namespace:" k8s/base/ || echo "OK — no namespace fields remain"
```
Expected: `OK — no namespace fields remain`

- [ ] **Step 3: Switch Kafka DNS to short-form in `k8s/base/infra/kafka-statefulset.yaml`**

Change these two env values (they currently embed `ai-soc.svc.cluster.local`, which would cross-wire staging into production's Kafka — Kustomize does not rewrite strings inside env values):

```yaml
            - name: KAFKA_CONTROLLER_QUORUM_VOTERS
              value: "1@kafka-0.kafka:9093"
```
and
```yaml
            - name: KAFKA_ADVERTISED_LISTENERS
              value: "PLAINTEXT://kafka-0.kafka:9092"
```

- [ ] **Step 4: Switch ConfigMap DNS to short-form in `k8s/base/configmap.yaml`**

```yaml
  KAFKA_BOOTSTRAP_SERVERS: "kafka-0.kafka:9092"
```
and
```yaml
  CHROMA_HOST: "chromadb"
```
(All other keys unchanged.)

- [ ] **Step 5: Verify no FQDN remains anywhere in base**

```bash
grep -rn "svc.cluster.local" k8s/base/ || echo "OK — no FQDNs remain"
```
Expected: `OK — no FQDNs remain`

- [ ] **Step 6: Create `k8s/base/kustomization.yaml`**

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - configmap.yaml
  - infra/kafka-statefulset.yaml
  - infra/kafka-service.yaml
  - infra/redis-statefulset.yaml
  - infra/redis-service.yaml
  - infra/postgres-statefulset.yaml
  - infra/postgres-service.yaml
  - infra/chromadb-statefulset.yaml
  - infra/chromadb-service.yaml
  - app/api-deployment.yaml
  - app/api-service.yaml
  - app/orchestrator-deployment.yaml
  - app/wazuh-bridge-deployment.yaml
```

- [ ] **Step 7: Validate base renders and its resources are schema-valid**

```bash
cd d:/ai_soc
kubectl kustomize k8s/base > /dev/null && echo "base renders OK"
find k8s/base -name '*.yaml' ! -name 'kustomization.yaml' -print0 | xargs -0 "$HOME/bin/kubeconform.exe" -strict -summary
```
Expected: `base renders OK`, then `Valid: 13, Invalid: 0, Errors: 0, Skipped: 0`

- [ ] **Step 8: Commit**

```bash
git add k8s/
git commit -m "refactor(k8s): restructure manifests into kustomize base with namespace-agnostic DNS"
```

---

### Task 2: Production overlay

**Files:**
- Create: `k8s/overlays/production/kustomization.yaml`
- Create: `k8s/overlays/production/namespace.yaml`

- [ ] **Step 1: Create `k8s/overlays/production/namespace.yaml`**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ai-soc
  labels:
    name: ai-soc
```

- [ ] **Step 2: Create `k8s/overlays/production/kustomization.yaml`**

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ai-soc
resources:
  - namespace.yaml
  - ../../base
images:
  - name: ghcr.io/amunim12/ai-soc-api
    newTag: latest
```

- [ ] **Step 3: Render and verify structure**

```bash
cd d:/ai_soc
kubectl kustomize k8s/overlays/production > /tmp/prod-render.yaml
grep -c "^kind:" /tmp/prod-render.yaml
grep -c "namespace: ai-soc$" /tmp/prod-render.yaml
grep -c "image: ghcr.io/amunim12/ai-soc-api:latest" /tmp/prod-render.yaml
grep -n "svc.cluster.local" /tmp/prod-render.yaml || echo "no FQDN OK"
```
Expected: `14` (kinds: 1 Namespace + 1 ConfigMap + 4 StatefulSets + 5 Services + 3 Deployments), `13` (every namespaced resource — the Namespace object itself has no namespace field), `3` (all three Deployments), `no FQDN OK`.

- [ ] **Step 4: Schema-validate the rendered output**

```bash
kubectl kustomize k8s/overlays/production | "$HOME/bin/kubeconform.exe" -strict -summary -
```
Expected: `Valid: 14, Invalid: 0, Errors: 0, Skipped: 0`

- [ ] **Step 5: Commit**

```bash
git add k8s/overlays/production/
git commit -m "feat(k8s): add production kustomize overlay"
```

---

### Task 3: Staging overlay

**Files:**
- Create: `k8s/overlays/staging/kustomization.yaml`
- Create: `k8s/overlays/staging/namespace.yaml`
- Create: `k8s/overlays/staging/delete-wazuh-bridge.yaml`

- [ ] **Step 1: Create `k8s/overlays/staging/namespace.yaml`**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ai-soc-staging
  labels:
    name: ai-soc-staging
```

- [ ] **Step 2: Create `k8s/overlays/staging/delete-wazuh-bridge.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-soc-wazuh-bridge
$patch: delete
```

- [ ] **Step 3: Create `k8s/overlays/staging/kustomization.yaml`**

Resource reductions are ~50% of base; PVCs shrink to 2Gi; the API Service moves to host port 8081 because K3s ServiceLB cannot bind two LoadBalancer Services to the same host port (production owns 8080):

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ai-soc-staging
resources:
  - namespace.yaml
  - ../../base
images:
  - name: ghcr.io/amunim12/ai-soc-api
    newTag: latest
patches:
  - path: delete-wazuh-bridge.yaml
  - target:
      kind: Service
      name: ai-soc-api
    patch: |-
      - op: replace
        path: /spec/ports/0/port
        value: 8081
  - target:
      kind: StatefulSet
      name: kafka
    patch: |-
      - op: replace
        path: /spec/volumeClaimTemplates/0/spec/resources/requests/storage
        value: 2Gi
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          requests:
            cpu: 125m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
  - target:
      kind: StatefulSet
      name: redis
    patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 250m
            memory: 128Mi
  - target:
      kind: StatefulSet
      name: postgres
    patch: |-
      - op: replace
        path: /spec/volumeClaimTemplates/0/spec/resources/requests/storage
        value: 2Gi
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          requests:
            cpu: 125m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
  - target:
      kind: StatefulSet
      name: chromadb
    patch: |-
      - op: replace
        path: /spec/volumeClaimTemplates/0/spec/resources/requests/storage
        value: 2Gi
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          requests:
            cpu: 125m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
  - target:
      kind: Deployment
      name: ai-soc-api
    patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          requests:
            cpu: 125m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
  - target:
      kind: Deployment
      name: ai-soc-orchestrator
    patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          requests:
            cpu: 250m
            memory: 256Mi
          limits:
            cpu: "1"
            memory: 512Mi
```

- [ ] **Step 4: Render and verify structure**

```bash
cd d:/ai_soc
kubectl kustomize k8s/overlays/staging > /tmp/staging-render.yaml
grep -c "^kind:" /tmp/staging-render.yaml
grep -c "namespace: ai-soc-staging$" /tmp/staging-render.yaml
grep -n "wazuh-bridge" /tmp/staging-render.yaml || echo "bridge absent OK"
grep -B3 -A1 "port: 8081" /tmp/staging-render.yaml
grep -c "storage: 2Gi" /tmp/staging-render.yaml
```
Expected: `13` kinds (14 minus the deleted bridge Deployment), `12` namespaced resources, `bridge absent OK`, the api Service block showing `port: 8081` with `targetPort: 8080`, and `4` storage lines at 2Gi (kafka/postgres/chromadb patched down + redis already 2Gi in base).

- [ ] **Step 5: Schema-validate the rendered output**

```bash
kubectl kustomize k8s/overlays/staging | "$HOME/bin/kubeconform.exe" -strict -summary -
```
Expected: `Valid: 13, Invalid: 0, Errors: 0, Skipped: 0`

- [ ] **Step 6: Commit**

```bash
git add k8s/overlays/staging/
git commit -m "feat(k8s): add staging kustomize overlay (port 8081, no bridge, reduced resources)"
```

---

### Task 4: Multi-namespace setup scripts + secret template DSN sync

**Files:**
- Rewrite: `scripts/k8s-setup-secrets.sh`
- Rewrite: `scripts/k8s-setup-secrets.ps1`
- Modify: `k8s/secret.example.yaml` (two DSN lines)

- [ ] **Step 1: Replace `scripts/k8s-setup-secrets.sh` in full**

```bash
#!/usr/bin/env bash
set -euo pipefail

NAMESPACES=("ai-soc" "ai-soc-staging")

echo "AI SOC — K3s secrets + site config setup (production + staging)"
echo "================================================================"

read -rp "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host): " HOST_IP
if [ -z "$HOST_IP" ]; then
  echo "Error: host IP is required." >&2
  exit 1
fi

# Ensure namespaces exist; find which ones still need a secret.
NEED_SECRET=()
for ns in "${NAMESPACES[@]}"; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
  if kubectl get secret ai-soc-secrets --namespace "$ns" >/dev/null 2>&1; then
    echo "ai-soc-secrets already exists in $ns — leaving it untouched to avoid rotating"
    echo "credentials that the Postgres/Redis PVCs were initialised with."
    echo "To rotate deliberately: kubectl delete secret ai-soc-secrets -n $ns, then re-run."
  else
    NEED_SECRET+=("$ns")
  fi
done

if [ "${#NEED_SECRET[@]}" -gt 0 ]; then
  read -rp "Wazuh API user [wazuh]: " WAZUH_USER
  WAZUH_USER="${WAZUH_USER:-wazuh}"
  read -rsp "Wazuh API password (required): " WAZUH_PASSWORD
  echo ""
  if [ -z "$WAZUH_PASSWORD" ]; then
    echo "Error: Wazuh API password is required — the bridge cannot ingest alerts without it." >&2
    exit 1
  fi
  read -rp "Wazuh indexer user [admin]: " WAZUH_INDEXER_USER
  WAZUH_INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
  read -rsp "Wazuh indexer password [same as API password]: " WAZUH_INDEXER_PASSWORD
  echo ""
  WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-$WAZUH_PASSWORD}"

  for ns in "${NEED_SECRET[@]}"; do
    JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    DEFAULT_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(20))")
    POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    # Short-form service DNS resolves within the pod's own namespace, so the
    # same DSN shape works in both production and staging.
    POSTGRES_DSN="postgresql://soc:${POSTGRES_PASSWORD}@postgres-0.postgres:5432/soc_pipeline"
    REDIS_URL="redis://:${REDIS_PASSWORD}@redis-0.redis:6379/0"

    # SHUFFLE_API_KEY is intentionally a dummy value: the pydantic Settings class
    # requires the field to exist, but SOAR_ENABLED=false means it is never used.
    # If you enable SOAR, replace it with a real key from your Shuffle instance.
    kubectl create secret generic ai-soc-secrets \
      --namespace "$ns" \
      --from-literal=JWT_SECRET_KEY="$JWT_SECRET_KEY" \
      --from-literal=DEFAULT_ADMIN_PASSWORD="$DEFAULT_ADMIN_PASSWORD" \
      --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
      --from-literal=REDIS_PASSWORD="$REDIS_PASSWORD" \
      --from-literal=POSTGRES_DSN="$POSTGRES_DSN" \
      --from-literal=REDIS_URL="$REDIS_URL" \
      --from-literal=SHUFFLE_API_KEY="not-configured" \
      --from-literal=WAZUH_USER="$WAZUH_USER" \
      --from-literal=WAZUH_PASSWORD="$WAZUH_PASSWORD" \
      --from-literal=WAZUH_INDEXER_USER="$WAZUH_INDEXER_USER" \
      --from-literal=WAZUH_INDEXER_PASSWORD="$WAZUH_INDEXER_PASSWORD" \
      --dry-run=client -o yaml | kubectl apply -f -

    echo ""
    echo "[$ns] admin password (save this now, it will not be shown again): $DEFAULT_ADMIN_PASSWORD"
  done
fi

for ns in "${NAMESPACES[@]}"; do
  kubectl create configmap ai-soc-site-config \
    --namespace "$ns" \
    --from-literal=WAZUH_API_URL="https://${HOST_IP}:55000" \
    --from-literal=WAZUH_INDEXER_URL="https://${HOST_IP}:9200" \
    --from-literal=WAZUH_VERIFY_SSL="false" \
    --from-literal=LOCAL_LLM_BASE_URL="http://${HOST_IP}:8001/v1" \
    --from-literal=SHUFFLE_BASE_URL="http://${HOST_IP}:3443" \
    --dry-run=client -o yaml | kubectl apply -f -
done

echo ""
echo "Site config applied in namespaces: ${NAMESPACES[*]}."
```

- [ ] **Step 2: Syntax-check**

```bash
bash -n d:/ai_soc/scripts/k8s-setup-secrets.sh && echo "bash syntax OK"
```
Expected: `bash syntax OK`

- [ ] **Step 3: Replace `scripts/k8s-setup-secrets.ps1` in full**

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Create the ai-soc-secrets Secret and ai-soc-site-config ConfigMap in the
    production (ai-soc) and staging (ai-soc-staging) namespaces.
.NOTES
    Re-running is safe: existing ai-soc-secrets are left untouched per namespace
    (rotating them would break Postgres/Redis auth against PVC-initialised data);
    the site config is always re-applied.
#>
$ErrorActionPreference = "Stop"
$Namespaces = @("ai-soc", "ai-soc-staging")

function New-Secret([int]$Bytes) {
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($buf)
    $rng.Dispose()
    return (($buf | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Read-PlainPassword([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    if ($plain -and $plain.Contains('"')) {
        throw 'Passwords containing a double-quote (") are not supported by this Windows script - use scripts/k8s-setup-secrets.sh or choose a different password.'
    }
    return $plain
}

Write-Host "AI SOC - K3s secrets + site config setup (production + staging)"
Write-Host "================================================================"

$HostIp = Read-Host "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host)"
if ([string]::IsNullOrWhiteSpace($HostIp)) {
    throw "Host IP is required."
}

$NeedSecret = @()
foreach ($ns in $Namespaces) {
    kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f -

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $null = kubectl get secret ai-soc-secrets --namespace $ns 2>&1
    $secretExists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prevEAP

    if ($secretExists) {
        Write-Host "ai-soc-secrets already exists in $ns - leaving it untouched to avoid rotating"
        Write-Host "credentials that the Postgres/Redis PVCs were initialised with."
        Write-Host "To rotate deliberately: kubectl delete secret ai-soc-secrets -n $ns, then re-run."
    } else {
        $NeedSecret += $ns
    }
}

if ($NeedSecret.Count -gt 0) {
    $WazuhUser = Read-Host "Wazuh API user [wazuh]"
    if ([string]::IsNullOrWhiteSpace($WazuhUser)) { $WazuhUser = "wazuh" }
    $WazuhPassword = Read-PlainPassword "Wazuh API password (required)"
    if ([string]::IsNullOrWhiteSpace($WazuhPassword)) {
        throw "Wazuh API password is required - the bridge cannot ingest alerts without it."
    }
    $WazuhIndexerUser = Read-Host "Wazuh indexer user [admin]"
    if ([string]::IsNullOrWhiteSpace($WazuhIndexerUser)) { $WazuhIndexerUser = "admin" }
    $WazuhIndexerPassword = Read-PlainPassword "Wazuh indexer password [same as API password]"
    if ([string]::IsNullOrWhiteSpace($WazuhIndexerPassword)) { $WazuhIndexerPassword = $WazuhPassword }

    foreach ($ns in $NeedSecret) {
        $JwtSecretKey = New-Secret 64
        $DefaultAdminPassword = New-Secret 20
        $PostgresPassword = New-Secret 32
        $RedisPassword = New-Secret 32

        # Short-form service DNS resolves within the pod's own namespace, so the
        # same DSN shape works in both production and staging.
        $PostgresDsn = "postgresql://soc:$PostgresPassword@postgres-0.postgres:5432/soc_pipeline"
        $RedisUrl = "redis://:$RedisPassword@redis-0.redis:6379/0"

        # SHUFFLE_API_KEY is intentionally a dummy value: the pydantic Settings class
        # requires the field to exist, but SOAR_ENABLED=false means it is never used.
        # If you enable SOAR, replace it with a real key from your Shuffle instance.
        kubectl create secret generic ai-soc-secrets `
            --namespace $ns `
            --from-literal="JWT_SECRET_KEY=$JwtSecretKey" `
            --from-literal="DEFAULT_ADMIN_PASSWORD=$DefaultAdminPassword" `
            --from-literal="POSTGRES_PASSWORD=$PostgresPassword" `
            --from-literal="REDIS_PASSWORD=$RedisPassword" `
            --from-literal="POSTGRES_DSN=$PostgresDsn" `
            --from-literal="REDIS_URL=$RedisUrl" `
            --from-literal="SHUFFLE_API_KEY=not-configured" `
            --from-literal="WAZUH_USER=$WazuhUser" `
            --from-literal="WAZUH_PASSWORD=$WazuhPassword" `
            --from-literal="WAZUH_INDEXER_USER=$WazuhIndexerUser" `
            --from-literal="WAZUH_INDEXER_PASSWORD=$WazuhIndexerPassword" `
            --dry-run=client -o yaml | kubectl apply -f -

        Write-Host ""
        Write-Host "[$ns] admin password (save this now, it will not be shown again): $DefaultAdminPassword"
    }
}

foreach ($ns in $Namespaces) {
    kubectl create configmap ai-soc-site-config `
        --namespace $ns `
        --from-literal="WAZUH_API_URL=https://$($HostIp):55000" `
        --from-literal="WAZUH_INDEXER_URL=https://$($HostIp):9200" `
        --from-literal="WAZUH_VERIFY_SSL=false" `
        --from-literal="LOCAL_LLM_BASE_URL=http://$($HostIp):8001/v1" `
        --from-literal="SHUFFLE_BASE_URL=http://$($HostIp):3443" `
        --dry-run=client -o yaml | kubectl apply -f -
}

Write-Host ""
Write-Host "Site config applied in namespaces: $($Namespaces -join ', ')."
```

- [ ] **Step 4: Syntax-check via the PowerShell tool**

```powershell
$errors = $null
[System.Management.Automation.PSParser]::Tokenize((Get-Content d:/ai_soc/scripts/k8s-setup-secrets.ps1 -Raw), [ref]$errors) | Out-Null
if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Host $_.Message }; throw "Syntax errors found" } else { Write-Host "OK - no syntax errors" }
```
Expected: `OK - no syntax errors`

- [ ] **Step 5: Update the two DSN lines in `k8s/secret.example.yaml`**

Replace:
```yaml
  POSTGRES_DSN: "postgresql://soc:<POSTGRES_PASSWORD>@postgres-0.postgres.ai-soc.svc.cluster.local:5432/soc_pipeline"
  REDIS_URL: "redis://:<REDIS_PASSWORD>@redis-0.redis.ai-soc.svc.cluster.local:6379/0"
```
with:
```yaml
  POSTGRES_DSN: "postgresql://soc:<POSTGRES_PASSWORD>@postgres-0.postgres:5432/soc_pipeline"
  REDIS_URL: "redis://:<REDIS_PASSWORD>@redis-0.redis:6379/0"
```

Validate: `"$HOME/bin/kubeconform.exe" -strict k8s/secret.example.yaml` — expect exit 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/k8s-setup-secrets.sh scripts/k8s-setup-secrets.ps1 k8s/secret.example.yaml
git commit -m "feat(k8s): provision secrets and site config for both production and staging namespaces"
```

---

### Task 5: CI validation of rendered overlays

**Files:**
- Modify: `.github/workflows/pr-checks.yml` (the `k8s-validate` job only)

- [ ] **Step 1: Replace the `k8s-validate` job**

The job currently globs raw files (`find k8s -name '*.yaml' ...`), which now breaks on `kustomization.yaml` (kind Kustomization is not a cluster resource) and no longer validates what actually ships. Replace the entire job so it reads:

```yaml
  # ── Stage 8: K8s Manifest Validation ────────────────────────────────────
  k8s-validate:
    name: "Stage 8 · K8s Manifest Validation (kubeconform)"
    runs-on: ubuntu-latest
    needs: secrets-scan
    steps:
      - uses: actions/checkout@v6

      - name: Install kubeconform
        run: |
          curl -sL -o kubeconform.tar.gz \
            https://github.com/yannh/kubeconform/releases/download/v0.8.0/kubeconform-linux-amd64.tar.gz
          tar -xzf kubeconform.tar.gz
          chmod +x kubeconform
          sudo mv kubeconform /usr/local/bin/kubeconform

      - name: Install kustomize
        run: |
          curl -sL -o kustomize.tar.gz \
            "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.4.3/kustomize_v5.4.3_linux_amd64.tar.gz"
          tar -xzf kustomize.tar.gz
          chmod +x kustomize
          sudo mv kustomize /usr/local/bin/kustomize

      - name: Validate raw base manifests
        run: |
          find k8s/base -name '*.yaml' ! -name 'kustomization.yaml' -print0 \
            | xargs -0 kubeconform -strict -summary

      - name: Validate rendered production overlay
        run: kustomize build k8s/overlays/production | kubeconform -strict -summary -

      - name: Validate rendered staging overlay
        run: kustomize build k8s/overlays/staging | kubeconform -strict -summary -
```

- [ ] **Step 2: Verify YAML well-formedness**

```bash
python -c "import yaml,io; list(yaml.safe_load_all(io.open('.github/workflows/pr-checks.yml', encoding='utf-8')))" && echo "OK — valid YAML"
```
Expected: `OK — valid YAML`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/pr-checks.yml
git commit -m "ci: validate rendered kustomize overlays in k8s-validate"
```

---

### Task 6: Split release.yml Stage 5 into deploy-staging → approval → deploy-production

**Files:**
- Modify: `.github/workflows/release.yml` (everything from the `# ── Stage 5: Deploy to K3s (self-hosted runner) ───...` comment to end-of-file)

Before writing the e2e step, confirm the field name returned by `/api/activity`: check `get_activity` in `backend/infrastructure/postgres_client.py`. The verification code below sums `e.get('count', 0)` — if the column is named differently (e.g. `total`), adjust the python expression. As written, a wrong field name makes the check fail loudly (sums stay 0), never pass silently.

- [ ] **Step 1: Confirm the block location**

```bash
grep -n "Stage 5" d:/ai_soc/.github/workflows/release.yml
```
Expected: the Stage 5 comment header around line 293.

- [ ] **Step 2: Replace the entire Stage 5 block (comment line through end-of-file) with:**

```yaml
  # ── Stage 5a: Deploy to Staging (self-hosted runner) ─────────────────────
  deploy-staging:
    name: "Stage 5a · Deploy to Staging"
    runs-on: [self-hosted, k3s]
    needs: github-release
    # Only deploy tags that are not pre-releases
    if: "!contains(github.ref_name, '-rc') && !contains(github.ref_name, '-beta') && !contains(github.ref_name, '-alpha')"
    env:
      NAMESPACE: ai-soc-staging
    steps:
      - uses: actions/checkout@v6

      - name: Pin release image in staging overlay
        run: |
          sed -i "s|newTag: .*|newTag: ${{ github.ref_name }}|" k8s/overlays/staging/kustomization.yaml
          PINNED=$(kubectl kustomize k8s/overlays/staging | grep -c "image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}")
          if [ "$PINNED" != "2" ]; then
            echo "::error::Staging render contains $PINNED pinned image refs instead of 2 — image name or overlay images block drifted?"
            exit 1
          fi

      - name: Apply staging overlay
        run: kubectl apply -k k8s/overlays/staging

      - name: Wait for rollout
        run: |
          for deploy in ai-soc-api ai-soc-orchestrator; do
            kubectl rollout status deployment/"$deploy" \
              --namespace=${{ env.NAMESPACE }} \
              --timeout=5m
          done

      - name: Staging health check
        run: |
          for i in $(seq 1 10); do
            STATUS=$(curl -sf http://localhost:8081/health -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
              echo "Staging health check passed (attempt $i)"
              exit 0
            fi
            echo "Attempt $i: status=$STATUS — retrying in 10s"
            sleep 10
          done
          echo "Staging health check failed after 10 attempts"
          exit 1

      - name: End-to-end synthetic alert verification
        run: |
          sum_activity() {
            curl -sf http://localhost:8081/api/activity \
              | python3 -c "import json,sys; print(sum(int(e.get('count', 0)) for e in json.load(sys.stdin)))"
          }
          BEFORE=$(sum_activity || echo 0)
          echo "Activity count before injection: $BEFORE"
          kubectl exec -n ${{ env.NAMESPACE }} deployment/ai-soc-api -- \
            python -m scripts.synthetic_log_generator --eps 1 --duration 10
          for i in $(seq 1 24); do
            AFTER=$(sum_activity || echo 0)
            if [ "$AFTER" -gt "$BEFORE" ]; then
              echo "End-to-end verification passed: activity $BEFORE -> $AFTER (attempt $i)"
              exit 0
            fi
            echo "Attempt $i: activity still $AFTER — retrying in 5s"
            sleep 5
          done
          echo "::error::Synthetic alert never appeared in staging /api/activity — pipeline is not processing."
          exit 1

      - name: Report staging failure
        if: failure()
        run: |
          echo "::error::Staging deploy or verification failed for ${{ github.ref_name }}. Production was not touched. Staging is left running in namespace ${{ env.NAMESPACE }} for debugging."

  # ── Stage 5b: Promote to Production (manual approval via environment) ─────
  deploy-production:
    name: "Stage 5b · Promote to Production"
    runs-on: [self-hosted, k3s]
    needs: deploy-staging
    # The 'production' GitHub Environment must be configured with a required
    # reviewer (repo Settings → Environments → production) — that setting is
    # what turns this job into a manual approval gate. See docs/K3S_SETUP.md.
    environment: production
    env:
      NAMESPACE: ai-soc
    steps:
      - uses: actions/checkout@v6

      - name: Pin release image in production overlay
        run: |
          sed -i "s|newTag: .*|newTag: ${{ github.ref_name }}|" k8s/overlays/production/kustomization.yaml
          PINNED=$(kubectl kustomize k8s/overlays/production | grep -c "image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }}")
          if [ "$PINNED" != "3" ]; then
            echo "::error::Production render contains $PINNED pinned image refs instead of 3 — image name or overlay images block drifted?"
            exit 1
          fi

      - name: Apply production overlay
        run: kubectl apply -k k8s/overlays/production

      - name: Wait for rollout
        run: |
          # Note: orchestrator and wazuh-bridge have no readiness probes, so
          # rollout status only confirms their pods started — a config-driven
          # crash loop moments later is not caught here (see docs/K3S_SETUP.md).
          for deploy in ai-soc-api ai-soc-orchestrator ai-soc-wazuh-bridge; do
            kubectl rollout status deployment/"$deploy" \
              --namespace=${{ env.NAMESPACE }} \
              --timeout=5m
          done

      - name: Smoke test — health check
        run: |
          for i in $(seq 1 10); do
            STATUS=$(curl -sf http://localhost:8080/health -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
            if [ "$STATUS" = "200" ]; then
              echo "Health check passed (attempt $i)"
              exit 0
            fi
            echo "Attempt $i: status=$STATUS — retrying in 10s"
            sleep 10
          done
          echo "Health check failed after 10 attempts"
          exit 1

      - name: Rollback on failure
        if: failure()
        run: |
          ROLLBACK_FAILED=""
          for deploy in ai-soc-api ai-soc-orchestrator ai-soc-wazuh-bridge; do
            echo "Rolling back $deploy..."
            if ! kubectl rollout undo deployment/"$deploy" --namespace=${{ env.NAMESPACE }}; then
              echo "::warning::No previous revision for $deploy — nothing to roll back to (first deploy?)"
              ROLLBACK_FAILED="$ROLLBACK_FAILED $deploy"
              continue
            fi
            if ! kubectl rollout status deployment/"$deploy" --namespace=${{ env.NAMESPACE }} --timeout=3m; then
              ROLLBACK_FAILED="$ROLLBACK_FAILED $deploy"
            fi
          done
          if [ -n "$ROLLBACK_FAILED" ]; then
            echo "::error::Deploy failed and rollback did not complete cleanly for:$ROLLBACK_FAILED — manual intervention required."
          else
            echo "::error::Deploy failed — all deployments rolled back to the previous revision."
          fi

      - name: Scale down staging
        if: success()
        run: |
          # Return staging's resources to the host until the next release.
          # PVCs persist; kubectl apply -k in the next release's deploy-staging
          # job restores replicas: 1 from the manifests.
          kubectl scale statefulset,deployment --all --replicas=0 -n ai-soc-staging
          echo "Staging scaled to zero."
```

- [ ] **Step 3: Verify YAML well-formedness and job inventory**

```bash
python -c "import yaml,io; list(yaml.safe_load_all(io.open('.github/workflows/release.yml', encoding='utf-8')))" && echo "OK — valid YAML"
grep -nE "^  [a-z-]+:$" .github/workflows/release.yml
```
Expected: `OK — valid YAML`; the job list shows `build-sign`, `sbom-attest`, `build-electron`, `github-release`, `deploy-staging`, `deploy-production` (6 jobs — `deploy-k3s` is gone).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(cd): split deploy into staging gate with e2e verification and approved production promotion"
```

---

### Task 7: Runbook updates

**Files:**
- Modify: `docs/K3S_SETUP.md`

- [ ] **Step 1: Add a new subsection after §2's numbered list**

```markdown
### 2.1 One-time: production approval gate

`release.yml`'s `deploy-production` job pauses on the **production** GitHub
Environment. To make that pause a real approval gate (it is a no-op without
this): repo Settings → Environments → `production` → **Required reviewers** →
add the people allowed to approve production deploys. This is repository
configuration, not code — it cannot be committed, so treat this step as
mandatory setup.
```

- [ ] **Step 2: Update §3 (bootstrap)**

Replace the sentence:
```
It creates the `ai-soc-secrets` Secret and `ai-soc-site-config` ConfigMap.
**Save the admin password it prints — it is not stored anywhere else.**
```
with:
```markdown
It creates an independent `ai-soc-secrets` Secret and `ai-soc-site-config`
ConfigMap in **both** the `ai-soc` (production) and `ai-soc-staging`
namespaces — staging gets its own randomly generated credentials.
**Save the admin passwords it prints (one per namespace) — they are not
stored anywhere else.**
```

- [ ] **Step 3: Update §5 (first deploy)**

Replace §5's opening sentence ("Normally deployment happens automatically via `release.yml`'s `deploy-k3s` job on the next tagged release: it applies these same manifests idempotently and then updates the image on all three app Deployments (api, orchestrator, wazuh-bridge). To bootstrap manually before the first release:") with:

```markdown
Normally deployment happens automatically on the next tagged release:
`release.yml` first deploys to the `ai-soc-staging` namespace and verifies it
end-to-end with a synthetic alert (staging API listens on port **8081**), then
waits for a human to approve the **production** environment in the Actions UI,
and only then applies the production overlay and updates all three app
Deployments. After a successful promotion, staging is scaled to zero to return
its resources; its PVCs persist and the next release's staging deploy restores
it. To bootstrap production manually before the first release:
```

And replace the command block:
```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/infra/ -n ai-soc
kubectl apply -f k8s/app/ -n ai-soc
kubectl get pods -n ai-soc -w
```
with:
```bash
kubectl apply -k k8s/overlays/production
kubectl get pods -n ai-soc -w
```

- [ ] **Step 4: Append a staging bullet to §7 (Known limitations)**

```markdown
- **Staging shares the host's Wazuh but does not poll it.** The staging
  namespace runs the full pipeline minus the wazuh-bridge; release verification
  uses synthetic alerts. If you need staging to process real alerts ad-hoc,
  its secrets already contain the Wazuh credentials — deploy the bridge into
  `ai-soc-staging` manually from `k8s/base/app/wazuh-bridge-deployment.yaml`.
```

- [ ] **Step 5: Sanity-check internal consistency**

```bash
grep -n "8081\|ai-soc-staging\|apply -k\|Required reviewers" docs/K3S_SETUP.md | head -20
grep -n "apply -f k8s/namespace.yaml" docs/K3S_SETUP.md || echo "old commands gone OK"
```
Expected: hits for the new content; `old commands gone OK`.

- [ ] **Step 6: Commit**

```bash
git add docs/K3S_SETUP.md
git commit -m "docs(k8s): document staging gate, approval setup, and kustomize bootstrap in runbook"
```

---

## Plan self-review

**Spec coverage** — manifest restructure → Task 1; production overlay → Task 2; staging overlay (port 8081, bridge deletion, resource/PVC reductions) → Task 3; namespace-agnostic DNS → Task 1 (base) + Task 4 (script/template DSNs); image pinning via `images:` transformer + rendered-count assertion → Tasks 2/3 (transformer) and 6 (CI assertions: 2 staging / 3 production); release flow 5a/5b incl. e2e synthetic verification, approval gate, guarded rollback, staging scale-down → Task 6; rendered-overlay CI validation → Task 5; multi-namespace setup scripts + secret template sync → Task 4; runbook incl. the uncommittable approval-rule setup → Task 7. The spec's "prove the restructure is behavior-preserving" validation is covered by Task 2 Step 3's structural assertions (14 kinds, 13 namespaced, 3 images, no FQDN) — field-order-insensitive equivalents of a byte diff.

**Placeholder scan** — none. One deliberate verification hedge, stated inline at the top of Task 6: the e2e check sums a `count` field from `/api/activity`; the implementer confirms the field name against `get_activity` in `backend/infrastructure/postgres_client.py` and adjusts if needed. The code fails loudly (sums stay 0) rather than passing silently if the field name is wrong.

**Type/name consistency** — namespaces `ai-soc`/`ai-soc-staging`; overlay paths `k8s/overlays/{production,staging}`; image name `ghcr.io/amunim12/ai-soc-api` identical across both `images:` transformers, the sed `newTag` rewrites, and the render assertions; staging port 8081 consistent across the Service patch, health check, e2e poll, and runbook; deployment/container names unchanged from the existing manifests; pinned counts 2 (staging: api + orchestrator) and 3 (production) match the bridge deletion.
