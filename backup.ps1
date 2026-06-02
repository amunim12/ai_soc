# AI SOC — Backup Script
# Run daily via Task Scheduler: powershell -ExecutionPolicy Bypass -File backup.ps1
# Backs up: PostgreSQL, ChromaDB volume, Wazuh indexer snapshot

param(
    [string]$BackupDir = "d:\ai_soc\backups"
)

$ErrorActionPreference = "Stop"
$DATE = Get-Date -Format "yyyy-MM-dd"
$DEST = "$BackupDir\$DATE"
New-Item -ItemType Directory -Force $DEST | Out-Null

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Cyan }
function OK($msg)  { Write-Host "[OK] $msg" -ForegroundColor Green }
function ERR($msg) { Write-Host "[ERR] $msg" -ForegroundColor Red; exit 1 }

# ── PostgreSQL ────────────────────────────────────────────────────────────────
Log "Backing up PostgreSQL..."
$pgPass = "5nQKhXdX9etgO7yALvUpLWRh1IzZWnwk"
$pgFile = "$DEST\postgres-$DATE.sql.gz"
docker exec -e PGPASSWORD=$pgPass postgres pg_dump -U soc soc_pipeline |
    & { [System.IO.Compression.GZipStream]::new([System.IO.File]::OpenWrite($pgFile), [System.IO.Compression.CompressionMode]::Compress).Close() } 2>$null

# Simpler approach using docker exec piped to file
docker exec -e PGPASSWORD=$pgPass postgres pg_dump -U soc -Fc soc_pipeline |
    Set-Content -Encoding Byte "$DEST\postgres-$DATE.dump"
OK "PostgreSQL backup: $DEST\postgres-$DATE.dump"

# ── ChromaDB volume ───────────────────────────────────────────────────────────
Log "Backing up ChromaDB volume..."
docker run --rm `
    -v backend_chroma_data:/data:ro `
    -v "${DEST}:/out" `
    alpine sh -c "tar czf /out/chromadb-$DATE.tar.gz /data" 2>$null
OK "ChromaDB backup: $DEST\chromadb-$DATE.tar.gz"

# ── SQLite HITL database ──────────────────────────────────────────────────────
Log "Backing up SQLite HITL database..."
$sqliteSrc = "d:\ai_soc\ai_soc\backend\data\hitl.db"
if (Test-Path $sqliteSrc) {
    Copy-Item $sqliteSrc "$DEST\hitl-$DATE.db"
    OK "SQLite backup: $DEST\hitl-$DATE.db"
}

# ── Wazuh indexer snapshot ────────────────────────────────────────────────────
Log "Backing up Wazuh indexer (index snapshot)..."
try {
    # Register snapshot repo (idempotent)
    $snapRepo = '{"type":"fs","settings":{"location":"/tmp/wazuh-backup","compress":true}}'
    [System.IO.File]::WriteAllText("d:\ai_soc\_snap_repo.json", $snapRepo, [System.Text.Encoding]::ASCII)
    curl.exe -s -k -u "admin:SecretPassword" -X PUT "https://localhost:9200/_snapshot/wazuh_backup" `
        -H "Content-Type: application/json" --data-binary "@d:\ai_soc\_snap_repo.json" | Out-Null
    Remove-Item "d:\ai_soc\_snap_repo.json" -EA SilentlyContinue

    # Trigger snapshot
    $snapName = "snapshot-$DATE"
    curl.exe -s -k -u "admin:SecretPassword" -X PUT "https://localhost:9200/_snapshot/wazuh_backup/$snapName" `
        -H "Content-Type: application/json" -d '{"indices":"wazuh-*","ignore_unavailable":true}' | Out-Null
    OK "Wazuh snapshot triggered: $snapName"
} catch {
    ERR "Wazuh snapshot failed: $_"
}

# ── Rotate old backups (keep 7 days) ─────────────────────────────────────────
Log "Rotating backups older than 7 days..."
Get-ChildItem $BackupDir -Directory |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } |
    Remove-Item -Recurse -Force
OK "Backup rotation done"

Write-Host ""
Write-Host "Backup complete → $DEST" -ForegroundColor Green
Get-ChildItem $DEST | Select-Object Name, @{N='MB';E={[math]::Round($_.Length/1MB,1)}}
