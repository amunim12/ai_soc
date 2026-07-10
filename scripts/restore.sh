#!/usr/bin/env bash
# Restore AI SOC data volumes from a backup created by backup.sh.
# Usage: ./scripts/restore.sh <backup-dir>
#        ./scripts/restore.sh /mnt/nas/ai-soc-backups/20260101-120000
set -euo pipefail

BACKUP_DIR="${1:?Usage: ./scripts/restore.sh <backup-dir>}"

if [ ! -f "${BACKUP_DIR}/manifest.json" ]; then
    echo "Error: manifest.json not found in ${BACKUP_DIR}" >&2
    exit 1
fi

TIMESTAMP=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['timestamp'])" "${BACKUP_DIR}/manifest.json")

echo "Backup timestamp : $TIMESTAMP"
echo ""
echo "WARNING: This will OVERWRITE all current data volumes!"
read -rp "Type 'yes' to continue: " confirm
[ "$confirm" = "yes" ] || { echo "Aborted."; exit 0; }

restore_volume() {
    local volume="$1"
    local filename="$2"
    printf "  Restoring %s..." "$volume"
    docker run --rm \
        -v "${volume}:/data" \
        -v "${BACKUP_DIR}:/backup:ro" \
        alpine sh -c "find /data -mindepth 1 -delete 2>/dev/null; tar xzf /backup/$filename -C /data"
    echo " done."
}

echo ""
echo "Restoring AI SOC volumes..."
restore_volume "backend_pg_data"     "postgres-${TIMESTAMP}.tar.gz"
restore_volume "backend_redis_data"  "redis-${TIMESTAMP}.tar.gz"
restore_volume "backend_chroma_data" "chroma-${TIMESTAMP}.tar.gz"
restore_volume "backend_kafka_data"  "kafka-${TIMESTAMP}.tar.gz"

echo ""
echo "Restore complete."
echo "Restart services: docker compose -f docker-compose.full.yml --env-file backend/.env up -d"
