# AI SOC — On-Premises Deployment Guide

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 32 GB | 64 GB |
| GPU | NVIDIA 24 GB VRAM | NVIDIA A100 80 GB |
| Storage | 100 GB free (NVMe) | 500 GB NVMe |
| CPU | 8 cores | 32 cores |
| OS | Windows 10/11 · Ubuntu 22.04 | Ubuntu 22.04 LTS |
| Docker Desktop | 25.0+ | Latest |

---

## Option A — Desktop Installer (Recommended)

This is the easiest path. The installer bundles all configuration and starts services via a guided wizard.

1. Download the installer for your OS from the [Releases page](https://github.com/amunim12/ai_soc/releases/latest):
   - **Windows:** `AI SOC Setup X.Y.Z.exe`
   - **macOS:** `AI SOC X.Y.Z.dmg`
   - **Linux:** `AI SOC-X.Y.Z.AppImage` or `.deb`

2. Ensure **Docker Desktop** is running before launching.

3. Run the installer and follow the setup wizard:
   - Step 1: Docker check (auto-detected)
   - Step 2: Auto-generates all credentials (JWT, Postgres, Redis passwords)
   - Step 3: Configure your local vLLM endpoint
   - Step 4: Installs and starts all Docker services

4. Log in with the **admin** credentials shown during setup.

5. The app runs in your system tray. Services start automatically when the app opens.

> **Credential storage:** `.env` is written to `%APPDATA%\ai-soc\` (Windows) or `~/.config/ai-soc/` (Linux/Mac). Keep this file secure.

---

## Option B — Docker Compose (Advanced / Server)

### 1. Clone and configure

```bash
git clone https://github.com/amunim12/ai_soc.git
cd ai_soc
cp backend/.env.example backend/.env
```

Edit `backend/.env` — replace every `<CHANGE_ME>`:

```bash
# Generate JWT secret (required):
python3 -c "import secrets; print(secrets.token_hex(64))"

# Generate passwords:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Start the full stack

```bash
# Core pipeline (Kafka, Redis, Postgres, ChromaDB, FastAPI):
docker compose -f backend/docker-compose.yml --env-file backend/.env up -d

# Wait for healthy:
docker compose -f backend/docker-compose.yml ps
```

```bash
# Wazuh SIEM (single-node):
docker compose -f wazuh-docker/single-node/docker-compose.yml up -d
```

```bash
# Monitoring (Prometheus + Grafana) — optional but recommended:
GRAFANA_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))") \
  docker compose -f monitoring/docker-compose.monitoring.yml up -d
```

Or start everything at once:
```bash
docker compose -f docker-compose.full.yml --env-file backend/.env up -d
```

### 3. Start the local LLM (vLLM)

```bash
docker run --runtime nvidia --gpus all \
  -v ~/.cache/huggingface:/root/.cache/huggingface \
  -p 8001:8000 \
  vllm/vllm-openai:latest \
  --model Qwen/Qwen2.5-72B-Instruct-AWQ \
  --quantization awq \
  --max-model-len 8192
```

Set in `backend/.env`:
```
LOCAL_LLM_BASE_URL=http://localhost:8001/v1
LOCAL_LLM_MODEL=Qwen/Qwen2.5-72B-Instruct-AWQ
LOCAL_AI_ONLY=true
```

### 4. Open the frontend

```bash
cd frontend
npm install
npm run dev
# Opens at http://localhost:5173
```

Or launch the installed Electron app.

---

## Air-Gap Deployment

For networks with no internet access, pre-download all artifacts before disconnecting:

```bash
# Pull all Docker images:
docker pull apache/kafka:3.7.0
docker pull redis:7-alpine
docker pull chromadb/chroma:latest
docker pull postgres:16-alpine
docker pull prom/prometheus:v2.54.1
docker pull grafana/grafana:11.3.0
docker pull python:3.11-slim
docker pull alpine

# Save to tarballs:
docker save apache/kafka:3.7.0 | gzip > vendor/docker/kafka.tar.gz
# ... repeat for each image

# Pre-download Python dependencies:
cd backend
pip download -r requirements.txt -d vendor/python/

# Pre-download Node modules:
cd frontend && npm ci && tar czf ../vendor/node_modules.tar.gz node_modules/

# Download embedding model:
python3 -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
```

On the air-gapped machine:
```bash
# Load Docker images:
for f in vendor/docker/*.tar.gz; do docker load < "$f"; done

# Install Python deps from vendor:
pip install --no-index --find-links=vendor/python/ -r backend/requirements.txt
```

---

## Monitoring

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| AI SOC API | http://localhost:8080 | JWT token from `/api/auth/login` |
| API Metrics | http://localhost:8080/metrics | none (Prometheus scrapes this) |
| Prometheus | http://localhost:9090 | none |
| Grafana | http://localhost:3000 | admin / `$GRAFANA_PASSWORD` |
| Wazuh Dashboard | https://localhost:443 | admin / `<WAZUH_PASSWORD>` |

Grafana → **AI SOC Overview** dashboard is provisioned automatically.

---

## Backup & Restore

### Backup (Windows)
```powershell
.\scripts\backup.ps1 -OutputDir C:\ai-soc-backups
```

### Backup (Linux / macOS)
```bash
./scripts/backup.sh /mnt/backups
```

Backups contain compressed tar archives of all Docker volumes: Postgres, Redis, ChromaDB, Kafka.

### Restore
```powershell
# Windows:
.\scripts\restore.ps1 -BackupDir C:\ai-soc-backups\20260101-120000
```
```bash
# Linux:
./scripts/restore.sh /mnt/backups/20260101-120000
```

**Recommended schedule:** Daily backup, 30-day retention.

---

## Credential Rotation (Every 90 Days)

1. Stop all services: `docker compose -f docker-compose.full.yml down`
2. Generate new secrets:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(64))"  # JWT
   python3 -c "import secrets; print(secrets.token_hex(32))"  # passwords
   ```
3. Update `backend/.env` (or `%APPDATA%\ai-soc\.env` for desktop installs)
4. Restart: `docker compose -f docker-compose.full.yml --env-file backend/.env up -d`

---

## Upgrading

### Desktop App
The app checks for updates automatically every 4 hours. A dialog will appear when an update is available.

### Docker Compose
```bash
git pull origin main
docker compose -f backend/docker-compose.yml pull
docker compose -f backend/docker-compose.yml --env-file backend/.env up -d
```

---

## Port Reference

| Service | Port | Notes |
|---------|------|-------|
| AI SOC API | 8080 | FastAPI + HITL |
| Frontend (dev) | 5173 | Vite dev server |
| Kafka | 9092 | Alert ingestion |
| Redis | 6379 | Dedup + caching |
| PostgreSQL | 5432 | HITL audit log |
| ChromaDB | 8888 | Vector store |
| Wazuh Dashboard | 443 | SIEM UI |
| Wazuh Manager | 55000 | REST API |
| vLLM | 8001 | LLM inference |
| Prometheus | 9090 | Metrics |
| Grafana | 3000 | Dashboards |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| API returns 503 | Services not healthy | `docker compose ps` — wait for healthy status |
| LLM timeouts | vLLM not running | Check `LOCAL_LLM_BASE_URL` in `.env` |
| Kafka connection refused | Kafka still initialising | Wait 30–60 s after startup |
| ChromaDB OOM errors | Too many concurrent alerts | Lower `PIPELINE_MAX_CONCURRENT_ALERTS` |
| No alerts in dashboard | Wazuh agent misconfigured | Verify agent points to Kafka on port 9092 |
| Grafana shows no data | Prometheus not scraping | Check `http://localhost:9090/targets` |
| Docker compose won't start | `.env` missing `<CHANGE_ME>` values | Run setup wizard or edit `.env` manually |

---

## Security Hardening Checklist

- [ ] All `<CHANGE_ME>` values replaced with randomly generated secrets
- [ ] `backend/.env` permissions set to `600` (owner read-only)
- [ ] Docker socket not exposed to Shuffle unless on isolated VM
- [ ] Wazuh certificates regenerated (not using default certs)
- [ ] Firewall blocks all ports except those in the Port Reference above
- [ ] `USE_MOCK_TI=false` only if threat intel APIs are available on the network
- [ ] Backup schedule configured and tested
- [ ] 90-day credential rotation reminder set
