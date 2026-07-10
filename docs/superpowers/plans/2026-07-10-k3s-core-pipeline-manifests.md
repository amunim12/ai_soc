# K3s Core Pipeline Manifests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Kubernetes manifests, secrets/config bootstrap, K3s install runbook, and CD pipeline wiring so `release.yml`'s Stage 5 (`deploy-k3s`) has a real, working target to deploy to — a single-node on-prem K3s deployment of the AI SOC core pipeline (Kafka, Redis, Postgres, ChromaDB, API, orchestrator, Wazuh bridge), running alongside the existing Docker-Compose-managed Wazuh/Shuffle/monitoring/vLLM stacks on the same machine.

**Architecture:** Seven K8s workloads in a new `ai-soc` namespace — four `StatefulSet`s for stateful infra (Kafka, Redis, Postgres, ChromaDB) with `local-path` PVCs, and three `Deployment`s built from the existing `backend/Dockerfile.api` image with different container commands (`ai-soc-api` runs the FastAPI server, `ai-soc-orchestrator` runs the Kafka-consuming agent graph, `ai-soc-wazuh-bridge` runs the Wazuh→Kafka bridge). Secrets and site-specific config (host LAN IP for reaching Docker-Compose-managed services) are created imperatively by a setup script, never committed. Full design rationale: `docs/superpowers/specs/2026-07-10-k3s-core-pipeline-deployment-design.md`.

**Tech Stack:** Kubernetes (K3s 1.30+), raw YAML manifests (no Helm/Kustomize), `kubeconform` for schema validation, GitHub Actions self-hosted runner.

**Implementation notes (deliberate refinements over the design doc, with reasoning):**

1. **`type: LoadBalancer` instead of generic `NodePort` for the API Service.** Plain `NodePort` is restricted to the 30000–32767 range in vanilla Kubernetes, which would mean the API isn't reachable on port 8080 as `DEPLOYMENT.md`'s port-reference table promises. K3s ships a built-in ServiceLB (Klipper) that binds `type: LoadBalancer` Services directly to the requested port on the node's host network — no cloud LB, no extra install, and it lands on exactly port 8080.
2. **`ai-soc-api`'s container command overrides `Dockerfile.api`'s default CMD.** The Dockerfile's CMD serves `api.hitl_api:app`, a subset app used for local dev. `backend/main.py`'s own docstring says to run `uvicorn main:app` — that's the entrypoint that actually mounts every router (dashboard, auth, RAG, SIEM, SOAR). The K8s Deployment overrides `command`/`args` to run `main:app` so the deployed API serves full functionality.
3. **The Stage 5 smoke test curls from the runner itself, not via `kubectl exec` into the pod.** The original release.yml draft used `kubectl exec ... -- curl ...`, but `Dockerfile.api`'s base image (`python:3.11-slim-bookworm`) doesn't install `curl`, so that exec would fail regardless of app health. Since the self-hosted runner labeled `k3s` **is** the K3s node (single-node cluster) and the API Service is host-bound via ServiceLB, `curl http://localhost:8080/health` from the runner reaches the pod directly without needing anything installed in the container.

---

### Task 1: Directory setup, kubeconform, and Namespace manifest

**Files:**
- Create: `k8s/namespace.yaml`

- [ ] **Step 1: Create the `k8s/` directory structure**

```bash
mkdir -p d:/ai_soc/k8s/infra d:/ai_soc/k8s/app
```

- [ ] **Step 2: Install kubeconform (schema validator, no cluster required)**

```bash
mkdir -p /tmp/kubeconform-install && cd /tmp/kubeconform-install
curl -sL -o kubeconform.tar.gz https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-windows-amd64.tar.gz
tar -xzf kubeconform.tar.gz
mkdir -p "$HOME/bin"
mv kubeconform.exe "$HOME/bin/kubeconform.exe"
export PATH="$HOME/bin:$PATH"
kubeconform -v
```
Expected: prints a version string (e.g. `v0.6.7`). Add `export PATH="$HOME/bin:$PATH"` to `~/.bashrc` so later terminal sessions have it too.

- [ ] **Step 3: Confirm the namespace manifest doesn't exist yet (red)**

```bash
cd d:/ai_soc
kubeconform -strict k8s/namespace.yaml
```
Expected: FAIL — `k8s/namespace.yaml: could not find the path` (file doesn't exist yet).

- [ ] **Step 4: Write `k8s/namespace.yaml`**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ai-soc
  labels:
    name: ai-soc
```

- [ ] **Step 5: Validate (green)**

```bash
kubeconform -strict k8s/namespace.yaml
```
Expected: no output, exit code 0 (kubeconform is silent on success unless `-summary` is passed).

- [ ] **Step 6: Commit**

```bash
git add k8s/namespace.yaml
git commit -m "feat(k8s): add ai-soc namespace manifest"
```

---

### Task 2: ConfigMap (universal, non-site-specific config)

**Files:**
- Create: `k8s/configmap.yaml`

- [ ] **Step 1: Confirm it doesn't exist yet (red)**

```bash
kubeconform -strict k8s/configmap.yaml
```
Expected: FAIL — file not found.

- [ ] **Step 2: Write `k8s/configmap.yaml`**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ai-soc-config
  namespace: ai-soc
data:
  KAFKA_BOOTSTRAP_SERVERS: "kafka-0.kafka.ai-soc.svc.cluster.local:9092"
  KAFKA_GROUP_ID: "ai_soc"
  CHROMA_HOST: "chromadb.ai-soc.svc.cluster.local"
  CHROMA_PORT: "8888"
  JWT_ALGORITHM: "HS256"
  JWT_EXPIRE_MINUTES: "480"
  USE_MOCK_TI: "false"
  LOCAL_AI_ONLY: "true"
  SOAR_ENABLED: "false"
  LOG_LEVEL: "INFO"
  PIPELINE_MAX_CONCURRENT_ALERTS: "512"
  KAFKA_NUM_CONSUMER_WORKERS: "16"
  LLM_MAX_CONCURRENT_CALLS: "64"
  LLM_CALL_TIMEOUT_SECONDS: "30.0"
  PLAYBOOK_CACHE_TTL_SECONDS: "3600"
  RAG_CTX_CACHE_TTL_SECONDS: "3600"
```

- [ ] **Step 3: Validate (green)**

```bash
kubeconform -strict k8s/configmap.yaml
```
Expected: exit code 0.

- [ ] **Step 4: Commit**

```bash
git add k8s/configmap.yaml
git commit -m "feat(k8s): add ai-soc-config ConfigMap"
```

---

### Task 3: Secret template (documentation only, never applied)

**Files:**
- Create: `k8s/secret.example.yaml`

- [ ] **Step 1: Confirm it doesn't exist yet (red)**

```bash
kubeconform -strict k8s/secret.example.yaml
```
Expected: FAIL — file not found.

- [ ] **Step 2: Write `k8s/secret.example.yaml`**

```yaml
# Template only — do NOT run `kubectl apply -f` on this file and never commit
# real values here. The actual Secret is created imperatively by
# scripts/k8s-setup-secrets.sh (Task 11), the same way backend/.env.example
# documents shape without holding real credentials.
apiVersion: v1
kind: Secret
metadata:
  name: ai-soc-secrets
  namespace: ai-soc
type: Opaque
stringData:
  JWT_SECRET_KEY: "<CHANGE_ME - generate with: python3 -c \"import secrets; print(secrets.token_hex(64))\">"
  DEFAULT_ADMIN_PASSWORD: "<CHANGE_ME - generate with: python3 -c \"import secrets; print(secrets.token_hex(20))\">"
  POSTGRES_PASSWORD: "<CHANGE_ME - generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\">"
  REDIS_PASSWORD: "<CHANGE_ME - generate with: python3 -c \"import secrets; print(secrets.token_hex(32))\">"
  POSTGRES_DSN: "postgresql://soc:<POSTGRES_PASSWORD>@postgres-0.postgres.ai-soc.svc.cluster.local:5432/soc_pipeline"
  REDIS_URL: "redis://:<REDIS_PASSWORD>@redis-0.redis.ai-soc.svc.cluster.local:6379/0"
  SHUFFLE_API_KEY: "<CHANGE_ME - obtain from your Shuffle instance, or leave as 'not-configured' if SOAR_ENABLED=false>"
```

- [ ] **Step 3: Validate (green)**

```bash
kubeconform -strict k8s/secret.example.yaml
```
Expected: exit code 0.

- [ ] **Step 4: Commit**

```bash
git add k8s/secret.example.yaml
git commit -m "docs(k8s): add ai-soc-secrets template (documentation only)"
```

---

### Task 4: Kafka StatefulSet + headless Service

**Files:**
- Create: `k8s/infra/kafka-statefulset.yaml`
- Create: `k8s/infra/kafka-service.yaml`

- [ ] **Step 1: Confirm files don't exist yet (red)**

```bash
kubeconform -strict k8s/infra/kafka-statefulset.yaml k8s/infra/kafka-service.yaml
```
Expected: FAIL — files not found.

- [ ] **Step 2: Write `k8s/infra/kafka-statefulset.yaml`**

Settings mirror `backend/docker-compose.yml`'s `kafka` service exactly (KRaft mode, same partition/retention config), with the K8s-specific addition of the pod's stable DNS name used for `KAFKA_ADVERTISED_LISTENERS`/`KAFKA_CONTROLLER_QUORUM_VOTERS` (StatefulSet pod `kafka-0` + headless Service `kafka`):

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: kafka
  namespace: ai-soc
  labels:
    app: kafka
spec:
  serviceName: kafka
  replicas: 1
  selector:
    matchLabels:
      app: kafka
  template:
    metadata:
      labels:
        app: kafka
    spec:
      containers:
        - name: kafka
          image: apache/kafka:3.7.0
          ports:
            - containerPort: 9092
              name: plaintext
            - containerPort: 9093
              name: controller
          env:
            - name: KAFKA_NODE_ID
              value: "1"
            - name: KAFKA_PROCESS_ROLES
              value: "broker,controller"
            - name: KAFKA_CONTROLLER_QUORUM_VOTERS
              value: "1@kafka-0.kafka.ai-soc.svc.cluster.local:9093"
            - name: KAFKA_CONTROLLER_LISTENER_NAMES
              value: "CONTROLLER"
            - name: KAFKA_LISTENERS
              value: "PLAINTEXT://:9092,CONTROLLER://:9093"
            - name: KAFKA_ADVERTISED_LISTENERS
              value: "PLAINTEXT://kafka-0.kafka.ai-soc.svc.cluster.local:9092"
            - name: KAFKA_LISTENER_SECURITY_PROTOCOL_MAP
              value: "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT"
            - name: KAFKA_INTER_BROKER_LISTENER_NAME
              value: "PLAINTEXT"
            - name: KAFKA_AUTO_CREATE_TOPICS_ENABLE
              value: "false"
            - name: KAFKA_NUM_PARTITIONS
              value: "48"
            - name: KAFKA_DEFAULT_REPLICATION_FACTOR
              value: "1"
            - name: KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR
              value: "1"
            - name: KAFKA_LOG_RETENTION_HOURS
              value: "168"
            - name: KAFKA_LOG_RETENTION_BYTES
              value: "-1"
            - name: CLUSTER_ID
              value: "MkU3OEVBNTcwNTJENDM2Qg=="
          volumeMounts:
            - name: kafka-data
              mountPath: /var/lib/kafka/data
          resources:
            requests:
              cpu: "250m"
              memory: "512Mi"
            limits:
              cpu: "1"
              memory: "1Gi"
          readinessProbe:
            exec:
              command: ["/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", "localhost:9092", "--list"]
            initialDelaySeconds: 30
            periodSeconds: 20
            timeoutSeconds: 10
            failureThreshold: 10
          livenessProbe:
            exec:
              command: ["/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", "localhost:9092", "--list"]
            initialDelaySeconds: 40
            periodSeconds: 30
            timeoutSeconds: 10
            failureThreshold: 5
  volumeClaimTemplates:
    - metadata:
        name: kafka-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-path
        resources:
          requests:
            storage: 10Gi
```

- [ ] **Step 3: Write `k8s/infra/kafka-service.yaml`**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kafka
  namespace: ai-soc
  labels:
    app: kafka
spec:
  clusterIP: None
  selector:
    app: kafka
  ports:
    - name: plaintext
      port: 9092
      targetPort: 9092
    - name: controller
      port: 9093
      targetPort: 9093
```

- [ ] **Step 4: Validate (green)**

```bash
kubeconform -strict k8s/infra/kafka-statefulset.yaml k8s/infra/kafka-service.yaml
```
Expected: exit code 0.

- [ ] **Step 5: Commit**

```bash
git add k8s/infra/kafka-statefulset.yaml k8s/infra/kafka-service.yaml
git commit -m "feat(k8s): add Kafka StatefulSet and headless Service"
```

---

### Task 5: Redis StatefulSet + Service

**Files:**
- Create: `k8s/infra/redis-statefulset.yaml`
- Create: `k8s/infra/redis-service.yaml`

- [ ] **Step 1: Confirm files don't exist yet (red)**

```bash
kubeconform -strict k8s/infra/redis-statefulset.yaml k8s/infra/redis-service.yaml
```
Expected: FAIL — files not found.

- [ ] **Step 2: Write `k8s/infra/redis-statefulset.yaml`**

Mirrors `backend/docker-compose.yml`'s `redis` service (`--save 60 1 --loglevel warning --requirepass`), with the password pulled from the `ai-soc-secrets` Secret instead of a `.env` file:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: ai-soc
  labels:
    app: redis
spec:
  serviceName: redis
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: redis
          image: redis:7-alpine
          command: ["sh", "-c"]
          args:
            - "redis-server --save 60 1 --loglevel warning --requirepass \"$REDIS_PASSWORD\""
          ports:
            - containerPort: 6379
              name: redis
          env:
            - name: REDIS_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: ai-soc-secrets
                  key: REDIS_PASSWORD
          volumeMounts:
            - name: redis-data
              mountPath: /data
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
          readinessProbe:
            exec:
              command: ["sh", "-c", "redis-cli -a \"$REDIS_PASSWORD\" ping"]
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 5
          livenessProbe:
            exec:
              command: ["sh", "-c", "redis-cli -a \"$REDIS_PASSWORD\" ping"]
            initialDelaySeconds: 15
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 5
  volumeClaimTemplates:
    - metadata:
        name: redis-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-path
        resources:
          requests:
            storage: 2Gi
```

- [ ] **Step 3: Write `k8s/infra/redis-service.yaml`**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: ai-soc
  labels:
    app: redis
spec:
  clusterIP: None
  selector:
    app: redis
  ports:
    - name: redis
      port: 6379
      targetPort: 6379
```

- [ ] **Step 4: Validate (green)**

```bash
kubeconform -strict k8s/infra/redis-statefulset.yaml k8s/infra/redis-service.yaml
```
Expected: exit code 0.

- [ ] **Step 5: Commit**

```bash
git add k8s/infra/redis-statefulset.yaml k8s/infra/redis-service.yaml
git commit -m "feat(k8s): add Redis StatefulSet and headless Service"
```

---

### Task 6: Postgres StatefulSet + Service

**Files:**
- Create: `k8s/infra/postgres-statefulset.yaml`
- Create: `k8s/infra/postgres-service.yaml`

- [ ] **Step 1: Confirm files don't exist yet (red)**

```bash
kubeconform -strict k8s/infra/postgres-statefulset.yaml k8s/infra/postgres-service.yaml
```
Expected: FAIL — files not found.

- [ ] **Step 2: Write `k8s/infra/postgres-statefulset.yaml`**

Mirrors `backend/docker-compose.yml`'s `postgres` service. `PGDATA` is set to a subdirectory of the mount point (`/var/lib/postgresql/data/pgdata`) rather than the mount root — a standard fix for the `local-path` provisioner leaving a `lost+found` directory at the volume root, which trips up `initdb`'s "directory not empty" check:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: ai-soc
  labels:
    app: postgres
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          ports:
            - containerPort: 5432
              name: postgres
          env:
            - name: POSTGRES_USER
              value: "soc"
            - name: POSTGRES_DB
              value: "soc_pipeline"
            - name: PGDATA
              value: "/var/lib/postgresql/data/pgdata"
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: ai-soc-secrets
                  key: POSTGRES_PASSWORD
          volumeMounts:
            - name: pg-data
              mountPath: /var/lib/postgresql/data
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "1"
              memory: "512Mi"
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "soc", "-d", "soc_pipeline"]
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 5
          livenessProbe:
            exec:
              command: ["pg_isready", "-U", "soc", "-d", "soc_pipeline"]
            initialDelaySeconds: 15
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 5
  volumeClaimTemplates:
    - metadata:
        name: pg-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-path
        resources:
          requests:
            storage: 10Gi
```

- [ ] **Step 3: Write `k8s/infra/postgres-service.yaml`**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: ai-soc
  labels:
    app: postgres
spec:
  clusterIP: None
  selector:
    app: postgres
  ports:
    - name: postgres
      port: 5432
      targetPort: 5432
```

- [ ] **Step 4: Validate (green)**

```bash
kubeconform -strict k8s/infra/postgres-statefulset.yaml k8s/infra/postgres-service.yaml
```
Expected: exit code 0.

- [ ] **Step 5: Commit**

```bash
git add k8s/infra/postgres-statefulset.yaml k8s/infra/postgres-service.yaml
git commit -m "feat(k8s): add Postgres StatefulSet and headless Service"
```

---

### Task 7: ChromaDB StatefulSet + Service

**Files:**
- Create: `k8s/infra/chromadb-statefulset.yaml`
- Create: `k8s/infra/chromadb-service.yaml`

- [ ] **Step 1: Confirm files don't exist yet (red)**

```bash
kubeconform -strict k8s/infra/chromadb-statefulset.yaml k8s/infra/chromadb-service.yaml
```
Expected: FAIL — files not found.

- [ ] **Step 2: Write `k8s/infra/chromadb-statefulset.yaml`**

`backend/docker-compose.yml` uses `chromadb/chroma:latest`, which is unpinned — since this is new IaC, pin it to `0.5.23` to match the version already pinned in `backend/requirements.txt`'s `chromadb==0.5.23`, avoiding drift between the client library and server:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: chromadb
  namespace: ai-soc
  labels:
    app: chromadb
spec:
  serviceName: chromadb
  replicas: 1
  selector:
    matchLabels:
      app: chromadb
  template:
    metadata:
      labels:
        app: chromadb
    spec:
      containers:
        - name: chromadb
          image: chromadb/chroma:0.5.23
          ports:
            - containerPort: 8000
              name: http
          env:
            - name: CHROMA_SERVER_HOST
              value: "0.0.0.0"
            - name: CHROMA_SERVER_HTTP_PORT
              value: "8000"
            - name: IS_PERSISTENT
              value: "TRUE"
            - name: PERSIST_DIRECTORY
              value: "/chroma/chroma"
          volumeMounts:
            - name: chroma-data
              mountPath: /chroma/chroma
          resources:
            requests:
              cpu: "250m"
              memory: "512Mi"
            limits:
              cpu: "1"
              memory: "1Gi"
          readinessProbe:
            httpGet:
              path: /api/v2/heartbeat
              port: 8000
            initialDelaySeconds: 20
            periodSeconds: 15
            timeoutSeconds: 10
            failureThreshold: 5
          livenessProbe:
            httpGet:
              path: /api/v2/heartbeat
              port: 8000
            initialDelaySeconds: 30
            periodSeconds: 20
            timeoutSeconds: 10
            failureThreshold: 5
  volumeClaimTemplates:
    - metadata:
        name: chroma-data
      spec:
        accessModes: ["ReadWriteOnce"]
        storageClassName: local-path
        resources:
          requests:
            storage: 10Gi
```

- [ ] **Step 3: Write `k8s/infra/chromadb-service.yaml`**

Service port is `8888` (matching the app's existing `CHROMA_PORT` convention from `DEPLOYMENT.md`'s port-reference table and the Electron setup wizard), routed to the container's actual listening port `8000`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: chromadb
  namespace: ai-soc
  labels:
    app: chromadb
spec:
  clusterIP: None
  selector:
    app: chromadb
  ports:
    - name: http
      port: 8888
      targetPort: 8000
```

- [ ] **Step 4: Validate (green)**

```bash
kubeconform -strict k8s/infra/chromadb-statefulset.yaml k8s/infra/chromadb-service.yaml
```
Expected: exit code 0.

- [ ] **Step 5: Commit**

```bash
git add k8s/infra/chromadb-statefulset.yaml k8s/infra/chromadb-service.yaml
git commit -m "feat(k8s): add ChromaDB StatefulSet and headless Service (pinned to 0.5.23)"
```

---

### Task 8: API Deployment + LoadBalancer Service

**Files:**
- Create: `k8s/app/api-deployment.yaml`
- Create: `k8s/app/api-service.yaml`

- [ ] **Step 1: Confirm files don't exist yet (red)**

```bash
kubeconform -strict k8s/app/api-deployment.yaml k8s/app/api-service.yaml
```
Expected: FAIL — files not found.

- [ ] **Step 2: Write `k8s/app/api-deployment.yaml`**

Overrides `Dockerfile.api`'s default CMD to run `main:app` instead of `api.hitl_api:app` — see the plan-level "Implementation notes" above for why:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-soc-api
  namespace: ai-soc
  labels:
    app: ai-soc-api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ai-soc-api
  template:
    metadata:
      labels:
        app: ai-soc-api
    spec:
      containers:
        - name: api
          image: ghcr.io/amunim12/ai-soc-api:latest
          command: ["uvicorn"]
          args: ["main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
          ports:
            - containerPort: 8080
              name: http
          envFrom:
            - configMapRef:
                name: ai-soc-config
            - configMapRef:
                name: ai-soc-site-config
            - secretRef:
                name: ai-soc-secrets
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "1"
              memory: "512Mi"
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 5
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 20
            periodSeconds: 20
            timeoutSeconds: 5
            failureThreshold: 5
```

- [ ] **Step 3: Write `k8s/app/api-service.yaml`**

`type: LoadBalancer` uses K3s's built-in ServiceLB to bind port 8080 directly on the host — see "Implementation notes" above:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ai-soc-api
  namespace: ai-soc
  labels:
    app: ai-soc-api
spec:
  type: LoadBalancer
  selector:
    app: ai-soc-api
  ports:
    - name: http
      port: 8080
      targetPort: 8080
```

- [ ] **Step 4: Validate (green)**

```bash
kubeconform -strict k8s/app/api-deployment.yaml k8s/app/api-service.yaml
```
Expected: exit code 0.

- [ ] **Step 5: Commit**

```bash
git add k8s/app/api-deployment.yaml k8s/app/api-service.yaml
git commit -m "feat(k8s): add ai-soc-api Deployment and LoadBalancer Service"
```

---

### Task 9: Orchestrator Deployment

**Files:**
- Create: `k8s/app/orchestrator-deployment.yaml`

- [ ] **Step 1: Confirm it doesn't exist yet (red)**

```bash
kubeconform -strict k8s/app/orchestrator-deployment.yaml
```
Expected: FAIL — file not found.

- [ ] **Step 2: Write `k8s/app/orchestrator-deployment.yaml`**

Runs `python -m orchestration.graph` — the Kafka consumer loop that processes alerts through the multi-agent LangGraph pipeline (see `backend/orchestration/graph.py:184` `async def main()`, invoked via its `if __name__ == "__main__":` block). No HTTP surface, so no liveness/readiness probes — a crashed process is restarted by the Deployment controller's default `restartPolicy: Always`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-soc-orchestrator
  namespace: ai-soc
  labels:
    app: ai-soc-orchestrator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ai-soc-orchestrator
  template:
    metadata:
      labels:
        app: ai-soc-orchestrator
    spec:
      containers:
        - name: orchestrator
          image: ghcr.io/amunim12/ai-soc-api:latest
          command: ["python"]
          args: ["-m", "orchestration.graph"]
          envFrom:
            - configMapRef:
                name: ai-soc-config
            - configMapRef:
                name: ai-soc-site-config
            - secretRef:
                name: ai-soc-secrets
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "2"
              memory: "1Gi"
```

- [ ] **Step 3: Validate (green)**

```bash
kubeconform -strict k8s/app/orchestrator-deployment.yaml
```
Expected: exit code 0.

- [ ] **Step 4: Commit**

```bash
git add k8s/app/orchestrator-deployment.yaml
git commit -m "feat(k8s): add ai-soc-orchestrator Deployment"
```

---

### Task 10: Wazuh-bridge Deployment

**Files:**
- Create: `k8s/app/wazuh-bridge-deployment.yaml`

- [ ] **Step 1: Confirm it doesn't exist yet (red)**

```bash
kubeconform -strict k8s/app/wazuh-bridge-deployment.yaml
```
Expected: FAIL — file not found.

- [ ] **Step 2: Write `k8s/app/wazuh-bridge-deployment.yaml`**

Runs `python -m bridge.wazuh_kafka_bridge` (`backend/bridge/wazuh_kafka_bridge.py:211` `async def main()`), which reaches the host's Docker-Compose-managed Wazuh Manager via `WAZUH_MANAGER_HOST` (comes from the `ai-soc-site-config` ConfigMap, Task 11):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-soc-wazuh-bridge
  namespace: ai-soc
  labels:
    app: ai-soc-wazuh-bridge
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ai-soc-wazuh-bridge
  template:
    metadata:
      labels:
        app: ai-soc-wazuh-bridge
    spec:
      containers:
        - name: wazuh-bridge
          image: ghcr.io/amunim12/ai-soc-api:latest
          command: ["python"]
          args: ["-m", "bridge.wazuh_kafka_bridge"]
          envFrom:
            - configMapRef:
                name: ai-soc-config
            - configMapRef:
                name: ai-soc-site-config
            - secretRef:
                name: ai-soc-secrets
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
```

- [ ] **Step 3: Validate (green)**

```bash
kubeconform -strict k8s/app/wazuh-bridge-deployment.yaml
```
Expected: exit code 0.

- [ ] **Step 4: Commit**

```bash
git add k8s/app/wazuh-bridge-deployment.yaml
git commit -m "feat(k8s): add ai-soc-wazuh-bridge Deployment"
```

---

### Task 11: Secrets + site-config setup scripts

**Files:**
- Create: `scripts/k8s-setup-secrets.sh`
- Create: `scripts/k8s-setup-secrets.ps1`

These create the `ai-soc-secrets` Secret (Task 3's real counterpart) and a new `ai-soc-site-config` ConfigMap holding this specific machine's LAN IP-derived addresses for reaching the Docker-Compose-managed Wazuh Manager, vLLM, and Shuffle — referenced by `envFrom` in Tasks 8–10.

- [ ] **Step 1: Write `scripts/k8s-setup-secrets.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="ai-soc"

echo "AI SOC — K3s secrets + site config setup"
echo "=========================================="

read -rp "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host): " HOST_IP
if [ -z "$HOST_IP" ]; then
  echo "Error: host IP is required." >&2
  exit 1
fi

JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")
DEFAULT_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(20))")
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")

POSTGRES_DSN="postgresql://soc:${POSTGRES_PASSWORD}@postgres-0.postgres.${NAMESPACE}.svc.cluster.local:5432/soc_pipeline"
REDIS_URL="redis://:${REDIS_PASSWORD}@redis-0.redis.${NAMESPACE}.svc.cluster.local:6379/0"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic ai-soc-secrets \
  --namespace "$NAMESPACE" \
  --from-literal=JWT_SECRET_KEY="$JWT_SECRET_KEY" \
  --from-literal=DEFAULT_ADMIN_PASSWORD="$DEFAULT_ADMIN_PASSWORD" \
  --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  --from-literal=REDIS_PASSWORD="$REDIS_PASSWORD" \
  --from-literal=POSTGRES_DSN="$POSTGRES_DSN" \
  --from-literal=REDIS_URL="$REDIS_URL" \
  --from-literal=SHUFFLE_API_KEY="not-configured" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap ai-soc-site-config \
  --namespace "$NAMESPACE" \
  --from-literal=WAZUH_MANAGER_HOST="$HOST_IP" \
  --from-literal=LOCAL_LLM_BASE_URL="http://${HOST_IP}:8001/v1" \
  --from-literal=SHUFFLE_BASE_URL="http://${HOST_IP}:3443" \
  --dry-run=client -o yaml | kubectl apply -f -

echo ""
echo "Secrets + site config created in namespace '$NAMESPACE'."
echo "Admin password (save this now, it will not be shown again): $DEFAULT_ADMIN_PASSWORD"
```

- [ ] **Step 2: Make it executable and syntax-check it**

```bash
chmod +x d:/ai_soc/scripts/k8s-setup-secrets.sh
bash -n d:/ai_soc/scripts/k8s-setup-secrets.sh
```
Expected: no output (bash `-n` only checks syntax, doesn't execute).

- [ ] **Step 3: Write `scripts/k8s-setup-secrets.ps1`**

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Create the ai-soc-secrets Secret and ai-soc-site-config ConfigMap on the K3s cluster.
#>
$ErrorActionPreference = "Stop"
$Namespace = "ai-soc"

Write-Host "AI SOC - K3s secrets + site config setup"
Write-Host "=========================================="

$HostIp = Read-Host "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host)"
if ([string]::IsNullOrWhiteSpace($HostIp)) {
    throw "Host IP is required."
}

function New-Secret([int]$Bytes) {
    return (python3 -c "import secrets; print(secrets.token_hex($Bytes))").Trim()
}

$JwtSecretKey = New-Secret 64
$DefaultAdminPassword = New-Secret 20
$PostgresPassword = New-Secret 32
$RedisPassword = New-Secret 32

$PostgresDsn = "postgresql://soc:$PostgresPassword@postgres-0.postgres.$Namespace.svc.cluster.local:5432/soc_pipeline"
$RedisUrl = "redis://:$RedisPassword@redis-0.redis.$Namespace.svc.cluster.local:6379/0"

kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic ai-soc-secrets `
    --namespace $Namespace `
    --from-literal=JWT_SECRET_KEY=$JwtSecretKey `
    --from-literal=DEFAULT_ADMIN_PASSWORD=$DefaultAdminPassword `
    --from-literal=POSTGRES_PASSWORD=$PostgresPassword `
    --from-literal=REDIS_PASSWORD=$RedisPassword `
    --from-literal=POSTGRES_DSN=$PostgresDsn `
    --from-literal=REDIS_URL=$RedisUrl `
    --from-literal=SHUFFLE_API_KEY="not-configured" `
    --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap ai-soc-site-config `
    --namespace $Namespace `
    --from-literal=WAZUH_MANAGER_HOST=$HostIp `
    --from-literal=LOCAL_LLM_BASE_URL="http://$($HostIp):8001/v1" `
    --from-literal=SHUFFLE_BASE_URL="http://$($HostIp):3443" `
    --dry-run=client -o yaml | kubectl apply -f -

Write-Host ""
Write-Host "Secrets + site config created in namespace '$Namespace'."
Write-Host "Admin password (save this now, it will not be shown again): $DefaultAdminPassword"
```

- [ ] **Step 4: Syntax-check the PowerShell script**

```powershell
$errors = $null
[System.Management.Automation.PSParser]::Tokenize((Get-Content d:/ai_soc/scripts/k8s-setup-secrets.ps1 -Raw), [ref]$errors) | Out-Null
if ($errors.Count -gt 0) { throw "Syntax errors found" } else { Write-Host "OK — no syntax errors" }
```
Expected: `OK — no syntax errors`.

- [ ] **Step 5: Commit**

```bash
git add scripts/k8s-setup-secrets.sh scripts/k8s-setup-secrets.ps1
git commit -m "feat(k8s): add secrets + site-config bootstrap scripts"
```

---

### Task 12: K3s install, runner registration, and verification doc

**Files:**
- Create: `docs/K3S_SETUP.md`

- [ ] **Step 1: Write `docs/K3S_SETUP.md`**

```markdown
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
- `git` and Python 3 installed (the secrets-setup script shells out to
  `python3 -c "import secrets; ..."`, matching `DEPLOYMENT.md`'s existing pattern)

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

## 3. Bootstrap secrets and site config

Clone the repo onto this machine, then run the setup script once
(`scripts/k8s-setup-secrets.sh`):

```bash
cd ai-soc
./scripts/k8s-setup-secrets.sh
```

It prompts for this machine's LAN IP (used by in-cluster pods to reach the Wazuh
Manager, vLLM, and Shuffle running on the same host via Docker Compose) and
creates the `ai-soc-secrets` Secret and `ai-soc-site-config` ConfigMap. **Save the
admin password it prints — it is not stored anywhere else.**

## 4. Start the Docker-Compose-managed services

Wazuh, Shuffle, monitoring, and vLLM are not part of the K3s manifests — start
them exactly as documented in `DEPLOYMENT.md`'s "Option B — Docker Compose"
section, on this same machine.

## 5. First deploy

Normally the first `kubectl apply` happens automatically via `release.yml`'s
`deploy-k3s` job on the next tagged release. To bootstrap manually before the
first release (so there's something for `kubectl set image` to update later):

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/infra/ -n ai-soc
kubectl apply -f k8s/app/ -n ai-soc
kubectl get pods -n ai-soc -w
```
Expected: `kafka-0`, `redis-0`, `postgres-0`, `chromadb-0` reach `Running`/`Ready`,
then `ai-soc-api`, `ai-soc-orchestrator`, `ai-soc-wazuh-bridge` reach
`Running`/`Ready`.

## 6. Post-install verification

```bash
# API reachable on the host's LAN IP, port 8080:
curl http://localhost:8080/health
# Expected: {"status":"ok","service":"ai_soc_pipeline"}

# Wazuh bridge is reaching the host's Wazuh Manager:
kubectl logs -n ai-soc deployment/ai-soc-wazuh-bridge --tail=50
# Expected: no connection-refused errors against WAZUH_MANAGER_HOST

# Orchestrator is consuming from Kafka:
kubectl logs -n ai-soc deployment/ai-soc-orchestrator --tail=50
# Expected: consumer loop running, no crash loop

# End-to-end: generate a synthetic alert from the host and confirm it's processed
cd backend && python -m scripts.synthetic_log_generator --eps 1 --duration 10
```
Then check `http://localhost:8080/api/activity` shows the new alert within ~30s.

If any pod is stuck in `CrashLoopBackOff`, check `kubectl describe pod -n ai-soc
<pod-name>` and `kubectl logs -n ai-soc <pod-name> --previous`.
```

- [ ] **Step 2: Commit**

```bash
git add docs/K3S_SETUP.md
git commit -m "docs(k8s): add K3s install, runner registration, and verification runbook"
```

---

### Task 13: CI manifest validation job (kubeconform)

**Files:**
- Modify: `.github/workflows/pr-checks.yml`

Adds a lightweight, cluster-free schema validation job that runs on every PR touching `k8s/` — catches typos, wrong `apiVersion`s, and missing required fields before merge. This complements (doesn't replace) the existing `sast-iac` job, which already runs Checkov with `framework: dockerfile,kubernetes,yaml` and will start scanning `k8s/` automatically for misconfigurations once the manifests exist — Checkov checks security posture, kubeconform checks schema correctness.

- [ ] **Step 1: Update the stage list comment at the top of the file**

In `.github/workflows/pr-checks.yml`, find:
```yaml
#   6.  test-coverage    — pytest --cov with per-module gates
#   7.  dast             — OWASP ZAP API scan against live server
```
Replace with:
```yaml
#   6.  test-coverage    — pytest --cov with per-module gates
#   7.  dast             — OWASP ZAP API scan against live server
#   8.  k8s-validate     — kubeconform schema validation of k8s/ manifests
```

- [ ] **Step 2: Add the new job at the end of the file**

Append after the `dast` job (after line 537, the `kill $(cat /tmp/uvicorn.pid) || true` line that ends the file):

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
            https://github.com/yannh/kubeconform/releases/latest/download/kubeconform-linux-amd64.tar.gz
          tar -xzf kubeconform.tar.gz
          chmod +x kubeconform
          sudo mv kubeconform /usr/local/bin/kubeconform

      - name: Validate K8s manifests
        run: |
          find k8s -name '*.yaml' -print0 | xargs -0 kubeconform -strict -summary
```

- [ ] **Step 3: Verify the YAML is well-formed**

```bash
cd d:/ai_soc
python -c "import yaml; list(yaml.safe_load_all(open('.github/workflows/pr-checks.yml')))" && echo "OK — valid YAML"
```
Expected: `OK — valid YAML`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/pr-checks.yml
git commit -m "ci: add kubeconform validation job for k8s/ manifests"
```

---

### Task 14: Rewrite release.yml Stage 5 (apply + multi-deployment image update + rollback)

**Files:**
- Modify: `.github/workflows/release.yml:293-330`

Replaces the current `deploy-k3s` job, which only runs `kubectl set image` against a Deployment that's never created and only updates one of the three app Deployments. The new version applies all manifests idempotently, updates all three Deployments' images, and rolls back automatically if the rollout or smoke test fails (closing the "no rollback on failed deploy" gap identified earlier).

- [ ] **Step 1: Read the current Stage 5 block to confirm line range**

```bash
grep -n "Stage 5" d:/ai_soc/.github/workflows/release.yml
```
Expected: shows the comment header line and the `deploy-k3s:` job name line, confirming the block still starts around line 293–296 as originally reviewed.

- [ ] **Step 2: Replace the `deploy-k3s` job**

Replace the entire block from `  # ── Stage 5: Deploy to K3s (self-hosted runner) ───────────────────────────` through the end of the file with:

```yaml
  # ── Stage 5: Deploy to K3s (self-hosted runner) ───────────────────────────
  deploy-k3s:
    name: "Stage 5 · Deploy to K3s"
    runs-on: [self-hosted, k3s]
    needs: github-release
    # Only deploy tags that are not pre-releases
    if: "!contains(github.ref_name, '-rc') && !contains(github.ref_name, '-beta') && !contains(github.ref_name, '-alpha')"
    environment: production
    env:
      NAMESPACE: ai-soc
    steps:
      - uses: actions/checkout@v6

      - name: Apply K8s manifests (idempotent — creates on first run, updates on later runs)
        run: |
          kubectl apply -f k8s/namespace.yaml
          kubectl apply -f k8s/configmap.yaml
          kubectl apply -f k8s/infra/ -n ${{ env.NAMESPACE }}
          kubectl apply -f k8s/app/ -n ${{ env.NAMESPACE }}

      - name: Update deployment image tags
        run: |
          for deploy in ai-soc-api ai-soc-orchestrator ai-soc-wazuh-bridge; do
            container=$(echo "$deploy" | sed 's/ai-soc-//')
            kubectl set image deployment/"$deploy" \
              "$container"=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.ref_name }} \
              --namespace=${{ env.NAMESPACE }}
          done

      - name: Wait for rollout
        id: rollout
        run: |
          for deploy in ai-soc-api ai-soc-orchestrator ai-soc-wazuh-bridge; do
            kubectl rollout status deployment/"$deploy" \
              --namespace=${{ env.NAMESPACE }} \
              --timeout=5m
          done

      - name: Smoke test — health check
        id: smoke
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
          for deploy in ai-soc-api ai-soc-orchestrator ai-soc-wazuh-bridge; do
            echo "Rolling back $deploy..."
            kubectl rollout undo deployment/"$deploy" --namespace=${{ env.NAMESPACE }}
            kubectl rollout status deployment/"$deploy" --namespace=${{ env.NAMESPACE }} --timeout=3m || true
          done
          echo "::error::Deploy failed — rolled back to previous image."
```

Note: `curl http://localhost:8080/health` runs directly on the self-hosted runner (not via `kubectl exec`) — see the plan-level "Implementation notes" for why.

- [ ] **Step 3: Verify the YAML is well-formed**

```bash
cd d:/ai_soc
python -c "import yaml; list(yaml.safe_load_all(open('.github/workflows/release.yml')))" && echo "OK — valid YAML"
```
Expected: `OK — valid YAML`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "fix(cd): apply k8s manifests idempotently, update all 3 deployments, roll back on failed deploy"
```

---

## Plan self-review

**Spec coverage** — every section of `docs/superpowers/specs/2026-07-10-k3s-core-pipeline-deployment-design.md` maps to a task: scope/component list → Tasks 1, 4–10; secrets strategy → Tasks 3, 11; storage → embedded in Tasks 4–7; health checks → embedded in Tasks 4–9; resource limits → embedded in Tasks 4–10; K3s install + runner registration → Task 12; CD pipeline changes → Task 14; testing/validation plan → Task 13 (CI) + Task 12 §6 (manual runbook) + the kubeconform red/green step in every manifest task.

**Placeholder scan** — no `TBD`/`TODO` in any plan step. The only bracketed placeholders (`<CHANGE_ME - ...>`) live inside `k8s/secret.example.yaml`'s own content, which is an intentional documentation template (explicitly never applied), not a gap in the plan's instructions.

**Type/name consistency** — verified consistent across all tasks: namespace `ai-soc`; Secret `ai-soc-secrets` with keys `JWT_SECRET_KEY`, `DEFAULT_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `POSTGRES_DSN`, `REDIS_URL`, `SHUFFLE_API_KEY`; ConfigMaps `ai-soc-config` (Task 2) and `ai-soc-site-config` (Task 11, keys `WAZUH_MANAGER_HOST`/`LOCAL_LLM_BASE_URL`/`SHUFFLE_BASE_URL`); Deployments `ai-soc-api`/`ai-soc-orchestrator`/`ai-soc-wazuh-bridge` with container names `api`/`orchestrator`/`wazuh-bridge` respectively (matches the `sed 's/ai-soc-//'` transform in Task 14's image-update step); StatefulSets `kafka`/`redis`/`postgres`/`chromadb` with matching headless Service names, referenced consistently in `KAFKA_BOOTSTRAP_SERVERS`, `POSTGRES_DSN`, `REDIS_URL`, `CHROMA_HOST` across Tasks 2, 3, and 11.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-10-k3s-core-pipeline-manifests.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
