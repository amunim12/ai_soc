#Requires -Version 5.1
<#
.SYNOPSIS
    Restore AI SOC data volumes from a backup created by backup.ps1.

.PARAMETER BackupDir
    Path to the backup directory (contains manifest.json).

.EXAMPLE
    .\restore.ps1 -BackupDir .\backups\20260101-120000
#>
param(
    [Parameter(Mandatory)]
    [string]$BackupDir
)

$ErrorActionPreference = "Stop"
$manifest = Join-Path $BackupDir "manifest.json"

if (-not (Test-Path $manifest)) {
    Write-Error "manifest.json not found in $BackupDir"
    exit 1
}

$meta = Get-Content $manifest | ConvertFrom-Json
$timestamp = $meta.timestamp

Write-Host "Backup timestamp : $timestamp" -ForegroundColor Cyan
Write-Host "Created at       : $($meta.created_at)"
Write-Host ""
Write-Host "WARNING: This will OVERWRITE all current data volumes!" -ForegroundColor Red
$confirm = Read-Host "Type 'yes' to continue"
if ($confirm -ne "yes") { Write-Host "Aborted."; exit 0 }

function Restore-Volume {
    param([string]$VolumeName, [string]$FileName)
    Write-Host "  Restoring $VolumeName..." -NoNewline
    docker run --rm `
        -v "${VolumeName}:/data" `
        -v "${BackupDir}:/backup:ro" `
        alpine sh -c "rm -rf /data/* /data/..?* /data/.[!.]* 2>/dev/null; tar xzf /backup/$FileName -C /data"
    if ($LASTEXITCODE -ne 0) { throw "Restore failed for $VolumeName" }
    Write-Host " done." -ForegroundColor Green
}

Write-Host "`nRestoring AI SOC volumes..." -ForegroundColor Yellow
Restore-Volume "backend_pg_data"     "postgres-${timestamp}.tar.gz"
Restore-Volume "backend_redis_data"  "redis-${timestamp}.tar.gz"
Restore-Volume "backend_chroma_data" "chroma-${timestamp}.tar.gz"
Restore-Volume "backend_kafka_data"  "kafka-${timestamp}.tar.gz"

Write-Host "`nRestore complete." -ForegroundColor Green
Write-Host "Restart services: docker compose -f docker-compose.full.yml --env-file backend/.env up -d"
