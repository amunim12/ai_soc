# AI SOC — Production Stop Script
param([switch]$KeepDocker)

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Yellow }

Log "Stopping Python processes (backend, pipeline, bridge)..."
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match "uvicorn|orchestration.graph|wazuh_kafka_bridge" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; "  stopped PID $($_.ProcessId)" }

Log "Stopping nginx..."
docker rm -f aisoc-nginx 2>$null | Out-Null

if (-not $KeepDocker) {
    Log "Stopping Shuffle SOAR..."
    Set-Location "$PSScriptRoot\deploy\shuffle"; docker compose stop 2>$null | Out-Null

    Log "Stopping Wazuh cluster..."
    Set-Location "$PSScriptRoot\wazuh-docker\single-node"; docker compose stop 2>$null | Out-Null

    Log "Stopping infra containers..."
    Set-Location "$PSScriptRoot\backend"; docker compose stop kafka redis chromadb postgres 2>$null | Out-Null

    Log "Stopping vLLM..."
    docker stop vllm-qwen 2>$null | Out-Null
}

Write-Host "AI SOC stack stopped." -ForegroundColor Green
