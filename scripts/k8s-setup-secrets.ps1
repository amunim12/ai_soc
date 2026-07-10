#Requires -Version 5.1
<#
.SYNOPSIS
    Create the ai-soc-secrets Secret and ai-soc-site-config ConfigMap on the K3s cluster.
#>
$ErrorActionPreference = "Stop"
$Namespace = "ai-soc"

Write-Host "AI SOC - K3s secrets + site config setup"
Write-Host "=========================================="

$HostIp = Read-Host "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host)"
if ([string]::IsNullOrWhiteSpace($HostIp)) {
    throw "Host IP is required."
}

$WazuhUser = Read-Host "Wazuh API user [wazuh]"
if ([string]::IsNullOrWhiteSpace($WazuhUser)) { $WazuhUser = "wazuh" }
$WazuhPasswordSecure = Read-Host "Wazuh API password (required)" -AsSecureString
$WazuhPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($WazuhPasswordSecure))
if ([string]::IsNullOrWhiteSpace($WazuhPassword)) {
    throw "Wazuh API password is required - the bridge cannot ingest alerts without it."
}
$WazuhIndexerUser = Read-Host "Wazuh indexer user [admin]"
if ([string]::IsNullOrWhiteSpace($WazuhIndexerUser)) { $WazuhIndexerUser = "admin" }
$WazuhIndexerPasswordSecure = Read-Host "Wazuh indexer password [same as API password]" -AsSecureString
$WazuhIndexerPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($WazuhIndexerPasswordSecure))
if ([string]::IsNullOrWhiteSpace($WazuhIndexerPassword)) { $WazuhIndexerPassword = $WazuhPassword }

function New-Secret([int]$Bytes) {
    return (python3 -c "import secrets; print(secrets.token_hex($Bytes))").Trim()
}

$JwtSecretKey = New-Secret 64
$DefaultAdminPassword = New-Secret 20
$PostgresPassword = New-Secret 32
$RedisPassword = New-Secret 32

$PostgresDsn = "postgresql://soc:$PostgresPassword@postgres-0.postgres.$Namespace.svc.cluster.local:5432/soc_pipeline"
$RedisUrl = "redis://:$RedisPassword@redis-0.redis.$Namespace.svc.cluster.local:6379/0"

kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f -

# SHUFFLE_API_KEY is intentionally a dummy value: the pydantic Settings class
# requires the field to exist, but SOAR_ENABLED=false means it is never used.
# If you enable SOAR, replace it with a real key from your Shuffle instance.
kubectl create secret generic ai-soc-secrets `
    --namespace $Namespace `
    --from-literal=JWT_SECRET_KEY=$JwtSecretKey `
    --from-literal=DEFAULT_ADMIN_PASSWORD=$DefaultAdminPassword `
    --from-literal=POSTGRES_PASSWORD=$PostgresPassword `
    --from-literal=REDIS_PASSWORD=$RedisPassword `
    --from-literal=POSTGRES_DSN=$PostgresDsn `
    --from-literal=REDIS_URL=$RedisUrl `
    --from-literal=SHUFFLE_API_KEY="not-configured" `
    --from-literal=WAZUH_USER=$WazuhUser `
    --from-literal=WAZUH_PASSWORD=$WazuhPassword `
    --from-literal=WAZUH_INDEXER_USER=$WazuhIndexerUser `
    --from-literal=WAZUH_INDEXER_PASSWORD=$WazuhIndexerPassword `
    --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap ai-soc-site-config `
    --namespace $Namespace `
    --from-literal=WAZUH_API_URL="https://$($HostIp):55000" `
    --from-literal=WAZUH_INDEXER_URL="https://$($HostIp):9200" `
    --from-literal=WAZUH_VERIFY_SSL="false" `
    --from-literal=LOCAL_LLM_BASE_URL="http://$($HostIp):8001/v1" `
    --from-literal=SHUFFLE_BASE_URL="http://$($HostIp):3443" `
    --dry-run=client -o yaml | kubectl apply -f -

Write-Host ""
Write-Host "Secrets + site config created in namespace '$Namespace'."
Write-Host "Admin password (save this now, it will not be shown again): $DefaultAdminPassword"
