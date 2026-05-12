# AI SOC

An autonomous, multi-agent Security Operations Centre (SOC) pipeline built for air-gapped enterprise deployments. The system ingests raw security events from Wazuh, routes them through a supervised LangGraph agent graph, enriches them with threat intelligence, generates actionable playbooks, and executes them via a SOAR platform — all with Human-in-the-Loop (HITL) oversight at critical decision points.

> **Air-gap notice:** This system is designed to operate entirely on an isolated network. Every component — LLMs, embedding models, vector stores, message brokers — runs locally. No runtime internet access is required or permitted in production.

---

## Table of Contents

- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Threat Intelligence Integrations](#threat-intelligence-integrations)
- [License](#license)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          WAZUH SIEM CLUSTER                             │
│   Manager (55000) ── Indexer (9200) ── Dashboard (443)                  │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │  REST API polling (wazuh_kafka_bridge)
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         KAFKA (KRaft, 9092)                             │
│   Topics: wazuh.raw (24p) · wazuh.playbooks · wazuh.audit              │
│           wazuh.hitl-queue                                              │
└───────────────────────────┬─────────────────────────────────────────────┘
                            │  8 parallel consumer workers
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     LANGGRAPH SUPERVISOR PIPELINE                       │
│                                                                         │
│   ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐   │
│   │ log_analysis    │──▶│ threat_intel     │──▶│ playbook_gen     │   │
│   │ (LLM + rules)   │   │ (VT/OTX/Shodan/  │   │ (RAG + LLM)      │   │
│   └─────────────────┘   │  MISP/NVD/MITRE) │   └────────┬─────────┘   │
│                          └──────────────────┘            │             │
│                                                          ▼             │
│   ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐   │
│   │ soar_agent      │◀──│ hitl_agent       │◀──│ supervisor       │   │
│   │ (Shuffle SOAR)  │   │ (LISTEN/NOTIFY)  │   │ (confidence≥0.85)│   │
│   └─────────────────┘   └──────────────────┘   └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
    ┌──────────┐   ┌──────────────┐   ┌──────────┐
    │ Redis    │   │  PostgreSQL  │   │ ChromaDB │
    │ (6379)   │   │  (5432)      │   │ (8888)   │
    │ cache/   │   │  HITL store  │   │ RAG      │
    │ dedup    │   │  audit log   │   │ vectors  │
    └──────────┘   └──────────────┘   └──────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    FASTAPI (8000) + ELECTRON UI                         │
│   SIEM dashboard · SOAR dashboard · HITL queue · Auth (JWT)            │
└─────────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SHUFFLE SOAR (5001)                                │
│   Workflow execution · Automated response · OpenSearch backend          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Agent Pipeline Flow

```
Alert ingested
    │
    ▼
[log_analysis] → severity + IOC extraction
    │
    ├─ noise/duplicate → [drop]
    ├─ no IOCs → [playbook_gen] (skip enrichment)
    └─ IOCs found → [threat_intel]
                         │
                         ▼
                   [playbook_gen] ← RAG: MITRE ATT&CK, NVD, Wazuh rules,
                         │           past incidents, NIST CSF
                         │
                    confidence ≥ 0.85
                    AND non-critical
                    AND no irreversible steps?
                         │
                    ┌────┴────┐
                   YES       NO
                    │         │
                [execute]  [hitl] ← analyst review (PG LISTEN/NOTIFY)
                    │         │
                    │    ┌────┴─────────────────────────┐
                    │    │ APPROVE → [execute]           │
                    │    │ EDIT    → [playbook_gen]      │
                    │    │ REJECT  → [drop]              │
                    │    │ ESCALATE→ [escalate]          │
                    │    └──────────────────────────────┘
                    ▼
              [soar_agent] → Shuffle workflow
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| SIEM / EDR | Wazuh 4.10.2 (Manager + Indexer + Dashboard) |
| Message broker | Apache Kafka 3.7 (KRaft, no Zookeeper) |
| Pipeline orchestration | LangGraph 0.2 + LangChain Core 0.3 |
| LLM inference | Local vLLM (Meta-Llama-3.3-70B-Instruct-AWQ-INT4) |
| Vector store | ChromaDB 0.5 (persistent) |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2, offline) |
| Caching / dedup | Redis 7 |
| HITL persistence | PostgreSQL 16 (asyncpg, LISTEN/NOTIFY) |
| SQLite fallback | aiosqlite 0.20 |
| API server | FastAPI 0.115 + Uvicorn |
| SOAR | Shuffle (self-hosted) |
| Threat Intel | MISP · VirusTotal · OTX · Shodan · NVD · GeoIP2 |
| Auth | JWT (python-jose) + bcrypt |
| Frontend | Electron 28 + React 19 + Vite 7 + Tailwind CSS 4 |
| Container runtime | Docker Compose v2 |

---

## Prerequisites

### Hardware (minimum)

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 8 cores | 16 cores |
| RAM | 32 GB | 64 GB |
| Storage | 200 GB SSD | 500 GB NVMe |
| GPU | — | NVIDIA GPU ≥ 16 GB VRAM (for local LLM) |

### Software

- Docker Engine 24+ and Docker Compose v2
- Python 3.11–3.13 with a virtual environment
- Node.js 20 LTS (for the Electron frontend)
- Git (for cloning; not needed at runtime)

### Air-gap preparation (do this before isolating the machine)

All artifacts must be pulled while the machine still has internet access, then the network connection must be severed before running in production.

```bash
# 1. Pull all Docker images
docker compose -f backend/docker-compose.yml pull
docker compose -f deploy/shuffle/docker-compose.yml pull
docker compose -f wazuh-docker/single-node/docker-compose.yml pull

# 2. Download the embedding model
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# 3. Download Python dependencies into a local cache
pip download -r backend/requirements.txt -d ./vendor/python

# 4. Download Node dependencies
cd frontend && npm install && cd ..

# 5. Download the LLM (if using vLLM)
# Follow your vLLM provider's offline download instructions
# and place model weights in a local directory.
```

---

## Installation

```bash
# Clone (or copy via approved transfer medium in air-gapped environments)
git clone <internal-repo-url> fyp_se
cd fyp_se

# Create and activate Python virtualenv
python -m venv backend/.venv
source backend/.venv/bin/activate          # Linux/macOS
# backend\.venv\Scripts\activate           # Windows

# Install Python dependencies (offline: add --no-index --find-links=./vendor/python)
pip install -r backend/requirements.txt

# Install frontend dependencies
cd frontend && npm install && cd ..
```

---

## Configuration

Copy the example environment file and fill in every required value:

```bash
cp backend/.env.example backend/.env
```

### Required variables

```ini
# ── Local LLM ─────────────────────────────────────────────────────────────
LOCAL_LLM_BASE_URL=http://localhost:8001/v1
LOCAL_LLM_MODEL=hugging-quants/Meta-Llama-3.3-70B-Instruct-AWQ-INT4
LOCAL_LLM_API_KEY=local-vllm-key

# ── JWT ───────────────────────────────────────────────────────────────────
# Must be a random 64-byte hex string. Generate with:
#   python -c "import secrets; print(secrets.token_hex(64))"
JWT_SECRET_KEY=<CHANGE_ME>

# ── PostgreSQL ────────────────────────────────────────────────────────────
POSTGRES_DSN=postgresql://soc:<strong-password>@localhost:5432/soc_pipeline

# ── Kafka ─────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# ── Redis ─────────────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/0

# ── Wazuh ─────────────────────────────────────────────────────────────────
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_USER=wazuh
WAZUH_PASSWORD=<wazuh-api-password>

# ── Shuffle SOAR ──────────────────────────────────────────────────────────
SHUFFLE_BASE_URL=http://127.0.0.1:5001
SHUFFLE_API_KEY=<shuffle-api-key>
```

### Optional threat intelligence APIs

```ini
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
SHODAN_API_KEY=
MISP_URL=https://misp.local
MISP_API_KEY=
MAXMIND_DB_PATH=./data/GeoLite2-City.mmdb
```

> **Note:** When `USE_MOCK_TI=true` (default for development), the pipeline uses locally generated mock threat intelligence data instead of making any outbound API calls. Set to `false` only when the TI services are available on the local network.

---

## Running the System

Start all infrastructure services first, then each application component in a separate terminal.

### 1. Infrastructure (Kafka, Redis, PostgreSQL, ChromaDB)

```bash
docker compose -f backend/docker-compose.yml up -d
```

### 2. Wazuh SIEM cluster

```bash
docker compose -f wazuh-docker/single-node/docker-compose.yml up -d
```

### 3. Shuffle SOAR (optional)

```bash
docker compose -f deploy/shuffle/docker-compose.yml up -d
# Register workflows once after first start:
python -m scripts.register_shuffle_workflows
```

### 4. FastAPI backend

```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. LangGraph pipeline consumer

```bash
cd backend
python -m orchestration.graph
```

### 6. Wazuh–Kafka bridge (if using real Wazuh data)

```bash
cd backend
python -m bridge.wazuh_kafka_bridge
```

### 7. Synthetic load generator (development / load testing only)

```bash
cd backend
python -m scripts.synthetic_log_generator --eps 10 --duration 60
```

### 8. Electron desktop UI

```bash
cd frontend
npm run dev          # development hot-reload
npm run build:win    # production Windows build
```

---

## API Reference

All endpoints require a valid `Authorization: Bearer <token>` header unless noted.

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Issue JWT token |
| `GET` | `/api/auth/me` | Current user profile |
| `POST` | `/api/auth/users` | Create user (admin only) |
| `GET` | `/api/auth/users` | List users (admin only) |
| `GET` | `/api/auth/audit` | Auth audit log (admin only) |

### HITL queue

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/hitl/pending` | All pending analyst reviews |
| `GET` | `/api/hitl/{review_id}/status` | Review status |
| `POST` | `/api/hitl/{review_id}/decision` | Submit analyst decision |

### SIEM dashboard

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/siem/summary` | Headline metrics |
| `GET` | `/api/siem/alerts` | Recent alerts (limit 1–500) |
| `GET` | `/api/siem/severity` | Per-hour severity breakdown |
| `GET` | `/api/siem/mitre` | Top MITRE ATT&CK techniques |
| `GET` | `/api/siem/agents` | Monitored agent list |

### SOAR dashboard

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/soar-dash/workflows` | Shuffle workflow registry |
| `GET` | `/api/soar-dash/executions` | Execution history |
| `GET` | `/api/soar-dash/telemetry` | Per-hour execution counts |
| `GET` | `/api/soar-dash/audit` | Combined audit log |

### Pipeline metrics

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/metrics` | Aggregate SOC pipeline metrics |
| `GET` | `/api/activity` | Per-hour alert activity |
| `GET` | `/api/agents` | Agent health status |
| `GET` | `/api/rules/top` | Top triggered rules |
| `GET` | `/health` | Service health check |

### RAG knowledge base

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/rag/upload` | Upload document (PDF/DOCX) |
| `GET` | `/api/rag/collections` | List collections |
| `POST` | `/api/rag/query` | Semantic search |

---

## Project Structure

```
fyp_se/
├── backend/                    # Python backend — pipeline, API, agents
│   ├── agents/                 # LangGraph agent implementations
│   │   ├── hitl_agent.py       # Human-in-the-loop review agent
│   │   ├── log_analysis_agent.py
│   │   ├── playbook_gen_agent.py
│   │   ├── soar_agent.py
│   │   ├── supervisor.py       # Routing logic + confidence thresholds
│   │   └── threat_intel_agent.py
│   ├── api/                    # FastAPI routers
│   │   ├── auth_api.py
│   │   ├── hitl_api.py
│   │   ├── rag_api.py
│   │   ├── siem_api.py
│   │   ├── soar_api.py
│   │   └── soar_routes.py
│   ├── bridge/                 # External data ingestion
│   │   └── wazuh_kafka_bridge.py
│   ├── config/                 # Pydantic settings
│   ├── infrastructure/         # Clients: Kafka, Redis, Postgres, Chroma
│   ├── integrations/           # Threat intelligence adapters
│   ├── orchestration/          # LangGraph graph definition + state
│   ├── schemas/                # Pydantic data models
│   ├── scripts/                # Utility scripts
│   ├── services/               # Shuffle SOAR client
│   ├── tests/                  # Pytest test suite
│   ├── data/                   # Runtime data (SQLite DB, GeoIP DB)
│   ├── docker-compose.yml      # Infrastructure services
│   ├── Dockerfile.api          # FastAPI container image
│   ├── main.py                 # FastAPI application entry point
│   └── requirements.txt
├── frontend/                   # Electron + React desktop application
│   └── src/
│       ├── main/               # Electron main process
│       ├── preload/            # Electron preload scripts
│       └── renderer/           # React UI (Vite + Tailwind)
├── deploy/
│   └── shuffle/                # Shuffle SOAR deployment config
│       ├── docker-compose.yml
│       └── .env
├── wazuh-docker/               # Wazuh SIEM cluster deployment
│   ├── single-node/
│   └── multi-node/
└── docs/                       # Operational documentation
    └── STARTUP_COMMANDS.md
```

---

## Testing

```bash
cd backend
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=. --cov-report=term-missing

# Run a specific test module
pytest tests/test_hitl_agent.py -v
```

The test suite uses `fakeredis` and mock Kafka/Chroma clients so no live infrastructure is required to run tests.

---

## Threat Intelligence Integrations

| Source | Type | Air-gap support |
|---|---|---|
| MISP | IOC platform | Yes — self-hosted |
| VirusTotal | IOC lookup | Requires connectivity or cache |
| OTX (AlienVault) | Threat feeds | Requires connectivity or cache |
| Shodan | IP intelligence | Requires connectivity or cache |
| NVD | CVE database | Yes — local nvdlib cache |
| MITRE ATT&CK | TTP knowledge base | Yes — embedded in ChromaDB |
| GeoIP2 (MaxMind) | IP geolocation | Yes — local `.mmdb` file |

For full air-gap operation set `USE_MOCK_TI=true` or point VirusTotal/OTX/Shodan to internal proxies. MISP and NVD are natively self-hostable.

---

## License

This project is the intellectual property of the author and is submitted as a Final Year Project (FYP). All rights reserved. Redistribution or use outside the academic submission context requires explicit written permission.
