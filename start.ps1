# AI SOC — Production Startup Script
# Run from repo root: powershell -ExecutionPolicy Bypass -File start.ps1
# Starts all services in the correct order.

param(
    [switch]$SkipDocker,
    [switch]$SkipLLM,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Continue"
$ROOT   = $PSScriptRoot
$VENV   = "$ROOT\.venv\Scripts\python.exe"
$BACKEND = "$ROOT\backend"
$FRONTEND = "$ROOT\frontend"
$LOGS   = "d:\ai_soc\logs"

New-Item -ItemType Directory -Force $LOGS | Out-Null

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Cyan }
function OK($msg)  { Write-Host "[OK] $msg" -ForegroundColor Green }
function ERR($msg) { Write-Host "[ERR] $msg" -ForegroundColor Red }

# ── 1. vm.max_map_count (required by Wazuh indexer) ──────────────────────────
Log "Setting vm.max_map_count=262144 in Docker Desktop WSL2..."
wsl -d docker-desktop sysctl -w vm.max_map_count=262144 2>$null
OK "vm.max_map_count set"

if (-not $SkipDocker) {
    # ── 2. Infrastructure containers (Kafka, Redis, Chroma, Postgres) ────────
    Log "Starting infra containers..."
    Set-Location $BACKEND
    docker compose up -d kafka redis chromadb postgres 2>&1 | Out-Null
    OK "Infra containers started"

    # ── 3. Wazuh cluster ──────────────────────────────────────────────────────
    Log "Starting Wazuh single-node cluster..."
    Set-Location "$ROOT\wazuh-docker\single-node"
    docker compose up -d 2>&1 | Out-Null
    OK "Wazuh started"

    # ── 4. Shuffle SOAR ───────────────────────────────────────────────────────
    Log "Starting Shuffle SOAR..."
    Set-Location "$ROOT\deploy\shuffle"
    docker compose up -d 2>&1 | Out-Null
    OK "Shuffle started"

    # ── 5. vLLM (LLM inference) ───────────────────────────────────────────────
    if (-not $SkipLLM) {
        $hfCache = "$env:USERPROFILE\.cache\huggingface"
        $vllmRunning = docker ps --filter "name=vllm-qwen" --filter "status=running" -q
        if (-not $vllmRunning) {
            Log "Starting vLLM container..."
            docker run -d --runtime nvidia --gpus all `
                -v "${hfCache}:/root/.cache/huggingface" `
                -p 8001:8000 `
                --name vllm-qwen `
                --restart unless-stopped `
                vllm/vllm-openai:latest `
                --model Qwen/Qwen2.5-7B-Instruct-AWQ `
                --dtype half `
                --quantization awq `
                --max-model-len 8192 `
                --max-num-seqs 4 `
                --gpu-memory-utilization 0.93 `
                --trust-remote-code 2>&1 | Out-Null
            OK "vLLM container started (loading model ~90s)"
        } else {
            OK "vLLM already running"
        }
    }

    # ── Wait for Kafka to be healthy ──────────────────────────────────────────
    Log "Waiting for Kafka to be healthy..."
    $kafkaReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        $s = docker inspect kafka --format "{{.State.Health.Status}}" 2>$null
        if ($s -eq "healthy") { $kafkaReady = $true; break }
        Start-Sleep -Seconds 3
    }
    if ($kafkaReady) { OK "Kafka healthy" } else { ERR "Kafka not healthy after 90s — continuing anyway" }

    # ── Create Kafka topics (idempotent) ─────────────────────────────────────
    Log "Creating Kafka topics..."
    $topics = @{
        "wazuh.raw"="24 86400000"; "wazuh.analysed"="4 604800000"
        "wazuh.enriched"="4 604800000"; "wazuh.playbooks"="4 604800000"
        "wazuh.hitl-queue"="2 604800000"; "wazuh.soar-actions"="4 2592000000"
        "wazuh.audit"="4 7776000000"; "wazuh.feedback"="2 604800000"
    }
    foreach ($t in $topics.Keys) {
        $p,$r = $topics[$t].Split(" ")
        docker exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 `
            --create --if-not-exists --topic $t --partitions $p --replication-factor 1 `
            --config retention.ms=$r 1>$null 2>$null
    }
    OK "Kafka topics ensured"
}

# ── 6. FastAPI backend ────────────────────────────────────────────────────────
Log "Starting FastAPI backend..."
$env:ELECTRON_RUN_AS_NODE = $null
Remove-Item Env:\ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
Start-Process -FilePath $VENV `
    -ArgumentList "-m uvicorn main:app --host 0.0.0.0 --port 8000" `
    -WorkingDirectory $BACKEND `
    -RedirectStandardOutput "$LOGS\backend.log" `
    -RedirectStandardError  "$LOGS\backend-err.log" `
    -NoNewWindow

# Wait for backend
for ($i = 0; $i -lt 30; $i++) {
    try { $r = Invoke-WebRequest http://localhost:8000/health -UseBasicParsing -TimeoutSec 1 -EA Stop; if ($r.StatusCode -eq 200) { break } } catch {}
    Start-Sleep -Seconds 1
}
OK "FastAPI backend up at http://localhost:8000"

# ── 7. LangGraph pipeline consumer ───────────────────────────────────────────
Log "Starting LangGraph pipeline consumer..."
Start-Process -FilePath $VENV `
    -ArgumentList "-m orchestration.graph" `
    -WorkingDirectory $BACKEND `
    -RedirectStandardOutput "$LOGS\pipeline.log" `
    -RedirectStandardError  "$LOGS\pipeline-err.log" `
    -NoNewWindow
OK "Pipeline consumer started"

# ── 8. Wazuh-Kafka bridge ─────────────────────────────────────────────────────
Log "Starting Wazuh-Kafka bridge..."
Start-Process -FilePath $VENV `
    -ArgumentList "-m bridge.wazuh_kafka_bridge" `
    -WorkingDirectory $BACKEND `
    -RedirectStandardOutput "$LOGS\bridge.log" `
    -RedirectStandardError  "$LOGS\bridge-err.log" `
    -NoNewWindow
OK "Wazuh-Kafka bridge started"

# ── 9. Serve built web frontend via Docker nginx ──────────────────────────────
Log "Starting nginx web frontend..."
$frontendDist = "$ROOT\frontend\out\renderer"
if (Test-Path $frontendDist) {
    $existing = docker ps -q --filter "name=aisoc-nginx" 2>$null
    if ($existing) { docker rm -f aisoc-nginx 2>$null | Out-Null }
    docker run -d `
        --name aisoc-nginx `
        --restart unless-stopped `
        -p 3000:80 `
        -v "${frontendDist}:/usr/share/nginx/html:ro" `
        nginx:alpine 2>&1 | Out-Null
    OK "Frontend served at http://localhost:3000"
} else {
    ERR "Frontend not built — run: cd frontend && npm run build"
}

Write-Host ""
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host " AI SOC stack is up" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host " Web UI:          http://localhost:3000"
Write-Host " API:             http://localhost:8000"
Write-Host " API docs:        http://localhost:8000/docs"
Write-Host " Wazuh dashboard: https://localhost:443"
Write-Host " Shuffle SOAR:    http://localhost:3001"
Write-Host " vLLM:            http://localhost:8001/v1"
Write-Host " Logs:            $LOGS"
Write-Host "══════════════════════════════════════════════════" -ForegroundColor Yellow
