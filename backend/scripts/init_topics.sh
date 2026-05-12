#!/usr/bin/env bash
# init_topics.sh — Create all pipeline Kafka topics
# Run AFTER docker-compose up and Kafka is healthy

KAFKA_BIN="kafka-topics.sh"
BOOTSTRAP="localhost:9092"

echo "Creating Kafka topics..."

create_topic() {
  local TOPIC=$1
  local PARTITIONS=${2:-4}
  local REPLICATION=${3:-1}
  local RETENTION_MS=${4:-604800000}  # 7 days default

  $KAFKA_BIN --bootstrap-server "$BOOTSTRAP" \
    --create --if-not-exists \
    --topic "$TOPIC" \
    --partitions "$PARTITIONS" \
    --replication-factor "$REPLICATION" \
    --config retention.ms="$RETENTION_MS"

  echo "  ✓ $TOPIC"
}

# Raw Wazuh alerts — high throughput, 1-day retention
# 24 partitions allows up to 24 consumer processes in the supervisor group.
create_topic "wazuh.raw"        24 1 86400000

# Agent outputs — 7-day retention
create_topic "wazuh.analysed"   4 1 604800000
create_topic "wazuh.enriched"   4 1 604800000
create_topic "wazuh.playbooks"  4 1 604800000

# HITL queue — 7-day retention
create_topic "wazuh.hitl-queue" 2 1 604800000

# SOAR actions — 30-day retention
create_topic "wazuh.soar-actions" 4 1 2592000000

# Audit log — 90-day retention (compliance)
create_topic "wazuh.audit"      4 1 7776000000

# Feedback loop for RL
create_topic "wazuh.feedback"   2 1 604800000

echo ""
echo "All topics created. Listing:"
$KAFKA_BIN --bootstrap-server "$BOOTSTRAP" --list
