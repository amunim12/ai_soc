# Staging Gate for the K3s Release Pipeline

**Status:** Approved
**Date:** 2026-07-12
**Builds on:** `2026-07-10-k3s-core-pipeline-deployment-design.md` (the K3s core pipeline deployment, implemented on `feature/k3s-deployment`)

## Problem

A tagged release currently deploys straight to the production namespace; the only gate is the post-deploy health check (with rollback). There is no environment where the new version runs and processes alerts before production takes it, and no human approval point. The original CD-gap analysis called this out as "no staging gate / canary."

## Goal

Every stable release tag deploys to an isolated staging namespace on the same single-node K3s cluster, is verified end-to-end automatically, and is promoted to production only after a human approves — reusing one set of manifests for both environments.

## Consciously out of scope

- **Traffic-split canary.** With one replica per service, no ingress/mesh, and a single team of consumers, percentage-based traffic shifting is meaningless. The staging gate + manual approval + existing guarded rollback delivers the real risk reduction. Revisit only if the deployment ever gains an ingress and multiple replicas.
- Staging for the Docker-Compose-managed stacks (Wazuh, Shuffle, monitoring, vLLM).
- Multi-node HA.

## Design decisions (settled during brainstorming)

| Decision | Choice |
|---|---|
| Gate model | Auto-stage every stable tag → automated e2e verification → GitHub Environment manual approval → promote to production |
| Staging scope | Full stack (Kafka/Redis/Postgres/ChromaDB + api + orchestrator) minus wazuh-bridge; verification uses synthetic alerts, so the real Wazuh is never double-polled |
| Manifest mechanism | Kustomize base + overlays (`kubectl -k`, no new tooling on the cluster) — the "second environment" trigger the original spec named for revisiting raw YAML |
| Staging lifecycle | Scales to zero after successful promotion (frees ~half the stack's resources); stays up after a failed run for debugging |
| Verification depth | `/health` check plus a real end-to-end synthetic alert: inject via `kubectl exec`, poll `/api/activity` until the alert appears |

## Manifest restructure

```
k8s/
  secret.example.yaml            # unchanged, documentation only, never applied
  base/
    kustomization.yaml           # lists all resources below
    configmap.yaml               # namespace field removed; short-form DNS values
    infra/  (8 files)            # namespace fields removed; Kafka DNS short-form
    app/    (4 files)            # namespace fields removed
  overlays/
    production/
      kustomization.yaml         # namespace: ai-soc; images: newTag transformer
      namespace.yaml             # the ai-soc Namespace object
    staging/
      kustomization.yaml         # namespace: ai-soc-staging; images: newTag; patches
      namespace.yaml             # the ai-soc-staging Namespace object
      delete-wazuh-bridge.yaml   # $patch: delete for the bridge Deployment
      patch-resources.yaml       # ~50% resource requests/limits; 2Gi PVCs
      patch-api-service.yaml     # LoadBalancer port 8081 (host port 8080 is prod's)
```

Key points:

- **Namespace objects live in overlays**, not base — each environment owns its Namespace.
- **Port 8081 for staging API.** Two `LoadBalancer` Services cannot both bind host port 8080 under K3s ServiceLB. Staging's API Service is patched to port 8081; all staging verification targets `localhost:8081`.
- **Wazuh-bridge exclusion** via a strategic-merge `$patch: delete` in the staging overlay; base remains the single complete source of truth.

## Namespace-agnostic DNS (required correctness change to base)

Kustomize's namespace transformer rewrites `metadata.namespace`, **not** strings inside env values. The current manifests embed `...ai-soc.svc.cluster.local` in:

- Kafka StatefulSet: `KAFKA_ADVERTISED_LISTENERS`, `KAFKA_CONTROLLER_QUORUM_VOTERS`
- ConfigMap: `KAFKA_BOOTSTRAP_SERVERS`, `CHROMA_HOST`

Left as-is, staging pods would resolve **production's** Kafka — silently cross-wiring the environments. Fix: base switches to short-form DNS (`kafka-0.kafka:9092`, `chromadb`), which resolves inside whichever namespace the pod runs in via the pod's DNS search path. Every consumer of these names is in-namespace, so short-form is safe in both environments. The setup scripts' generated `POSTGRES_DSN`/`REDIS_URL` move to short-form for the same reason (`postgres-0.postgres:5432`, `redis-0.redis:6379`).

## Image pinning (replaces the sed-into-manifests approach)

Each overlay's `kustomization.yaml` carries an `images:` transformer:

```yaml
images:
  - name: ghcr.io/amunim12/ai-soc-api
    newTag: latest        # bootstrap default; CI rewrites this line per release
```

CI seds the single `newTag:` line in the target overlay, then renders with `kubectl kustomize` and **asserts the rendered output contains exactly 3 occurrences (production) / 2 occurrences (staging) of the pinned image ref** before applying — the existing drift-assertion guarantee carried into the new structure. `kubectl apply -k` remains the single owner of the image field, so revision history stays one-revision-per-release and `rollout undo` semantics are preserved.

## Release flow (`release.yml` Stage 5 splits into 5a/5b)

**`deploy-staging`** (self-hosted `k3s` runner; stable tags only; `needs: github-release`):
1. Sed `newTag` in `k8s/overlays/staging/kustomization.yaml`; render; assert pinned count = 2.
2. If staging was scaled to zero by a previous promotion, scale-up happens implicitly — `kubectl apply -k` restores `replicas: 1` from the manifests.
3. `kubectl apply -k k8s/overlays/staging`.
4. `kubectl rollout status` for `ai-soc-api` and `ai-soc-orchestrator` (5m timeout).
5. Verify: `curl localhost:8081/health` retry loop, then `kubectl exec` the staging api pod to run `scripts.synthetic_log_generator --eps 1 --duration 10`, then poll `http://localhost:8081/api/activity` (up to ~2 minutes) until the synthetic alert count appears. Fail the job if it never does.
6. On failure: no rollback needed (prod untouched); leave staging up for debugging; emit a clear `::error::`.

**`deploy-production`** (`needs: deploy-staging`; `environment: production`):
1. GitHub Environment protection rule (required reviewer) holds the job until a human approves in the Actions UI. **This rule is repo settings, not code** — documented as a mandatory one-time setup step in the runbook.
2. Sed `newTag` in the production overlay; render; assert pinned count = 3.
3. `kubectl apply -k k8s/overlays/production`.
4. Rollout waits for all three Deployments; smoke test `localhost:8080/health`; guarded truthful rollback on failure — all exactly as the current job does.
5. On success: scale staging to zero (`kubectl scale deployment,statefulset --all -n ai-soc-staging --replicas=0`) to return resources.

## Supporting changes

- **`pr-checks.yml` `k8s-validate`:** install a pinned kustomize (or use `kubectl kustomize`) and validate the **rendered** output of both overlays through kubeconform (`... | kubeconform -strict -`), instead of globbing raw files — validating what actually ships. Raw-file validation of base remains as a fast first pass.
- **Setup scripts (`k8s-setup-secrets.sh`/`.ps1`):** loop over `ai-soc` and `ai-soc-staging`, creating an independent `ai-soc-secrets` (fresh random values per namespace) and `ai-soc-site-config` in each. Prompts run once; Wazuh credentials are stored in both (staging doesn't run the bridge, but identical shape keeps `envFrom` uniform and lets staging run it ad-hoc if ever needed). Existing rotation guard applies per namespace. `k8s/secret.example.yaml`'s documented `POSTGRES_DSN`/`REDIS_URL` values update to the same short-form DNS so the template stays truthful to what the scripts generate.
- **`docs/K3S_SETUP.md`:** new sections — staging namespace, the one-time GitHub Environment approval-rule setup (Settings → Environments → production → Required reviewers), port 8081, the promotion flow, staging scale-down behavior, and updated §5 manual-bootstrap commands (`kubectl apply -k k8s/overlays/production`).

## Resource budget

Staging at ~50% requests adds roughly 0.9 CPU / 1.2Gi requests while active — acceptable against the 8-core/32GB host, and reclaimed after each promotion by the scale-to-zero step. PVCs (staging: 2Gi each) persist across scale-downs; total additional disk ~8Gi.

## Failure modes considered

- **Staging verification fails** → prod never sees the release; staging left running for diagnosis.
- **Approval never granted** → run sits pending until GitHub's environment timeout; nothing deployed.
- **Production deploy fails after approval** → existing guarded rollback restores the previous release; staging still holds the candidate for diagnosis.
- **Manifest image line drifts** → render-count assertion fails the job before anything touches the cluster.
- **Overlay/base rendering breaks in a PR** → `k8s-validate` renders both overlays and fails the PR.

## Testing / validation plan

- CI: rendered-overlay kubeconform validation on every PR touching `k8s/`.
- Local: `kubectl kustomize k8s/overlays/staging | kubeconform -strict -` (and production) during implementation; diff rendered production output against the pre-restructure manifests to prove the restructure is behavior-preserving (only namespace/DNS-form changes expected).
- On-cluster: first staging deploy verified via the §5/§6 runbook flow on port 8081.
