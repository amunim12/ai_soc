#!/usr/bin/env bash
# Backup AI SOC persistent Docker volumes to compressed archives.
# Usage: ./scripts/backup.sh [output-dir]
#        ./scripts/backup.sh /mnt/nas/ai-soc-backups
set -euo pipefail

OUTPUT_DIR="${1:-./backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="${OUTPUT_DIR}/${TIMESTAMP}"

mkdir -p "$BACKUP_DIR"
echo "Backup directory: $BACKUP_DIR"

backup_volume() {
    local volume="$1"
    local filename="$2"
    printf "  Backing up %s..." "$volume"
    docker run --rm \
        -v "${volume}:/data:ro" \
        -v "${BACKUP_DIR}:/backup" \
        alpine tar czf "/backup/$filename" -C /data .
    local size
    size=$(du -sh "${BACKUP_DIR}/${filename}" | cut -f1)
    echo " -> $filename ($size)"
}

echo ""
echo "Starting AI SOC backup..."
backup_volume "backend_pg_data"     "postgres-${TIMESTAMP}.tar.gz"
backup_volume "backend_redis_data"  "redis-${TIMESTAMP}.tar.gz"
backup_volume "backend_chroma_data" "chroma-${TIMESTAMP}.tar.gz"
backup_volume "backend_kafka_data"  "kafka-${TIMESTAMP}.tar.gz"

cat > "${BACKUP_DIR}/manifest.json" <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "volumes": ["postgres", "redis", "chroma", "kafka"],
  "backup_path": "${BACKUP_DIR}"
}
EOF

echo ""
echo "Backup complete: $BACKUP_DIR"
echo "To restore: ./scripts/restore.sh \"${BACKUP_DIR}\""
