#Requires -Version 5.1
<#
.SYNOPSIS
    Backup AI SOC persistent data volumes to compressed archives.

.PARAMETER OutputDir
    Directory to write backup archives. Default: .\backups

.EXAMPLE
    .\backup.ps1
    .\backup.ps1 -OutputDir C:\ai-soc-backups
#>
param(
    [string]$OutputDir = ".\backups"
)

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupPath = Join-Path $OutputDir $timestamp

New-Item -ItemType Directory -Force -Path $backupPath | Out-Null
Write-Host "Backup directory: $backupPath" -ForegroundColor Cyan

function Backup-Volume {
    param([string]$VolumeName, [string]$FileName)
    $dest = Join-Path $backupPath $FileName
    Write-Host "  Backing up volume: $VolumeName" -NoNewline
    docker run --rm `
        -v "${VolumeName}:/data:ro" `
        -v "${backupPath}:/backup" `
        alpine tar czf "/backup/$FileName" -C /data .
    if ($LASTEXITCODE -ne 0) { throw "Backup failed for $VolumeName" }
    $size = [math]::Round((Get-Item $dest).Length / 1MB, 2)
    Write-Host " -> $FileName ($size MB)" -ForegroundColor Green
}

Write-Host "`nStarting AI SOC backup..." -ForegroundColor Yellow
Backup-Volume "backend_pg_data"     "postgres-${timestamp}.tar.gz"
Backup-Volume "backend_redis_data"  "redis-${timestamp}.tar.gz"
Backup-Volume "backend_chroma_data" "chroma-${timestamp}.tar.gz"
Backup-Volume "backend_kafka_data"  "kafka-${timestamp}.tar.gz"

# Write manifest
@{
    timestamp    = $timestamp
    created_at   = (Get-Date -Format "o")
    volumes      = @("postgres", "redis", "chroma", "kafka")
    backup_path  = $backupPath
} | ConvertTo-Json | Out-File -FilePath (Join-Path $backupPath "manifest.json") -Encoding utf8

Write-Host "`nBackup complete: $backupPath" -ForegroundColor Green
Write-Host "To restore: .\scripts\restore.ps1 -BackupDir `"$backupPath`""
