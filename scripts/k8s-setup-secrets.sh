#!/usr/bin/env bash
set -euo pipefail

NAMESPACES=("ai-soc" "ai-soc-staging")

echo "AI SOC — K3s secrets + site config setup (production + staging)"
echo "================================================================"

read -rp "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host): " HOST_IP
if [ -z "$HOST_IP" ]; then
  echo "Error: host IP is required." >&2
  exit 1
fi

# Ensure namespaces exist; find which ones still need a secret.
NEED_SECRET=()
for ns in "${NAMESPACES[@]}"; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
  if kubectl get secret ai-soc-secrets --namespace "$ns" >/dev/null 2>&1; then
    echo "ai-soc-secrets already exists in $ns — leaving it untouched to avoid rotating"
    echo "credentials that the Postgres/Redis PVCs were initialised with."
    echo "To rotate deliberately: kubectl delete secret ai-soc-secrets -n $ns, then re-run."
  else
    NEED_SECRET+=("$ns")
  fi
done

if [ "${#NEED_SECRET[@]}" -gt 0 ]; then
  read -rp "Wazuh API user [wazuh]: " WAZUH_USER
  WAZUH_USER="${WAZUH_USER:-wazuh}"
  read -rsp "Wazuh API password (required): " WAZUH_PASSWORD
  echo ""
  if [ -z "$WAZUH_PASSWORD" ]; then
    echo "Error: Wazuh API password is required — the bridge cannot ingest alerts without it." >&2
    exit 1
  fi
  read -rp "Wazuh indexer user [admin]: " WAZUH_INDEXER_USER
  WAZUH_INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
  read -rsp "Wazuh indexer password [same as API password]: " WAZUH_INDEXER_PASSWORD
  echo ""
  WAZUH_INDEXER_PASSWORD="${WAZUH_INDEXER_PASSWORD:-$WAZUH_PASSWORD}"

  for ns in "${NEED_SECRET[@]}"; do
    JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    DEFAULT_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(20))")
    POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")

    # Short-form service DNS resolves within the pod's own namespace, so the
    # same DSN shape works in both production and staging.
    POSTGRES_DSN="postgresql://soc:${POSTGRES_PASSWORD}@postgres-0.postgres:5432/soc_pipeline"
    REDIS_URL="redis://:${REDIS_PASSWORD}@redis-0.redis:6379/0"

    # SHUFFLE_API_KEY is intentionally a dummy value: the pydantic Settings class
    # requires the field to exist, but SOAR_ENABLED=false means it is never used.
    # If you enable SOAR, replace it with a real key from your Shuffle instance.
    kubectl create secret generic ai-soc-secrets \
      --namespace "$ns" \
      --from-literal=JWT_SECRET_KEY="$JWT_SECRET_KEY" \
      --from-literal=DEFAULT_ADMIN_PASSWORD="$DEFAULT_ADMIN_PASSWORD" \
      --from-literal=POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
      --from-literal=REDIS_PASSWORD="$REDIS_PASSWORD" \
      --from-literal=POSTGRES_DSN="$POSTGRES_DSN" \
      --from-literal=REDIS_URL="$REDIS_URL" \
      --from-literal=SHUFFLE_API_KEY="not-configured" \
      --from-literal=WAZUH_USER="$WAZUH_USER" \
      --from-literal=WAZUH_PASSWORD="$WAZUH_PASSWORD" \
      --from-literal=WAZUH_INDEXER_USER="$WAZUH_INDEXER_USER" \
      --from-literal=WAZUH_INDEXER_PASSWORD="$WAZUH_INDEXER_PASSWORD" \
      --dry-run=client -o yaml | kubectl apply -f -

    echo ""
    echo "[$ns] admin password (save this now, it will not be shown again): $DEFAULT_ADMIN_PASSWORD"
  done
fi

for ns in "${NAMESPACES[@]}"; do
  kubectl create configmap ai-soc-site-config \
    --namespace "$ns" \
    --from-literal=WAZUH_API_URL="https://${HOST_IP}:55000" \
    --from-literal=WAZUH_INDEXER_URL="https://${HOST_IP}:9200" \
    --from-literal=WAZUH_VERIFY_SSL="false" \
    --from-literal=LOCAL_LLM_BASE_URL="http://${HOST_IP}:8001/v1" \
    --from-literal=SHUFFLE_BASE_URL="http://${HOST_IP}:3443" \
    --dry-run=client -o yaml | kubectl apply -f -
done

echo ""
echo "Site config applied in namespaces: ${NAMESPACES[*]}."
