#Requires -Version 5.1
<#
.SYNOPSIS
    Create the ai-soc-secrets Secret and ai-soc-site-config ConfigMap in the
    production (ai-soc) and staging (ai-soc-staging) namespaces.
.NOTES
    Re-running is safe: existing ai-soc-secrets are left untouched per namespace
    (rotating them would break Postgres/Redis auth against PVC-initialised data);
    the site config is always re-applied.
#>
$ErrorActionPreference = "Stop"
$Namespaces = @("ai-soc", "ai-soc-staging")

function New-Secret([int]$Bytes) {
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($buf)
    $rng.Dispose()
    return (($buf | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Read-PlainPassword([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    if ($plain -and $plain.Contains('"')) {
        throw 'Passwords containing a double-quote (") are not supported by this Windows script - use scripts/k8s-setup-secrets.sh or choose a different password.'
    }
    return $plain
}

Write-Host "AI SOC - K3s secrets + site config setup (production + staging)"
Write-Host "================================================================"

$HostIp = Read-Host "Host LAN IP for this machine (used by in-cluster pods to reach Wazuh/vLLM/Shuffle on the host)"
if ([string]::IsNullOrWhiteSpace($HostIp)) {
    throw "Host IP is required."
}

$NeedSecret = @()
foreach ($ns in $Namespaces) {
    kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f -

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $null = kubectl get secret ai-soc-secrets --namespace $ns 2>&1
    $secretExists = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prevEAP

    if ($secretExists) {
        Write-Host "ai-soc-secrets already exists in $ns - leaving it untouched to avoid rotating"
        Write-Host "credentials that the Postgres/Redis PVCs were initialised with."
        Write-Host "To rotate deliberately: kubectl delete secret ai-soc-secrets -n $ns, then re-run."
    } else {
        $NeedSecret += $ns
    }
}

if ($NeedSecret.Count -gt 0) {
    $WazuhUser = Read-Host "Wazuh API user [wazuh]"
    if ([string]::IsNullOrWhiteSpace($WazuhUser)) { $WazuhUser = "wazuh" }
    $WazuhPassword = Read-PlainPassword "Wazuh API password (required)"
    if ([string]::IsNullOrWhiteSpace($WazuhPassword)) {
        throw "Wazuh API password is required - the bridge cannot ingest alerts without it."
    }
    $WazuhIndexerUser = Read-Host "Wazuh indexer user [admin]"
    if ([string]::IsNullOrWhiteSpace($WazuhIndexerUser)) { $WazuhIndexerUser = "admin" }
    $WazuhIndexerPassword = Read-PlainPassword "Wazuh indexer password [same as API password]"
    if ([string]::IsNullOrWhiteSpace($WazuhIndexerPassword)) { $WazuhIndexerPassword = $WazuhPassword }

    foreach ($ns in $NeedSecret) {
        $JwtSecretKey = New-Secret 64
        $DefaultAdminPassword = New-Secret 20
        $PostgresPassword = New-Secret 32
        $RedisPassword = New-Secret 32

        # Short-form service DNS resolves within the pod's own namespace, so the
        # same DSN shape works in both production and staging.
        $PostgresDsn = "postgresql://soc:$PostgresPassword@postgres-0.postgres:5432/soc_pipeline"
        $RedisUrl = "redis://:$RedisPassword@redis-0.redis:6379/0"

        # SHUFFLE_API_KEY is intentionally a dummy value: the pydantic Settings class
        # requires the field to exist, but SOAR_ENABLED=false means it is never used.
        # If you enable SOAR, replace it with a real key from your Shuffle instance.
        kubectl create secret generic ai-soc-secrets `
            --namespace $ns `
            --from-literal="JWT_SECRET_KEY=$JwtSecretKey" `
            --from-literal="DEFAULT_ADMIN_PASSWORD=$DefaultAdminPassword" `
            --from-literal="POSTGRES_PASSWORD=$PostgresPassword" `
            --from-literal="REDIS_PASSWORD=$RedisPassword" `
            --from-literal="POSTGRES_DSN=$PostgresDsn" `
            --from-literal="REDIS_URL=$RedisUrl" `
            --from-literal="SHUFFLE_API_KEY=not-configured" `
            --from-literal="WAZUH_USER=$WazuhUser" `
            --from-literal="WAZUH_PASSWORD=$WazuhPassword" `
            --from-literal="WAZUH_INDEXER_USER=$WazuhIndexerUser" `
            --from-literal="WAZUH_INDEXER_PASSWORD=$WazuhIndexerPassword" `
            --dry-run=client -o yaml | kubectl apply -f -

        Write-Host ""
        Write-Host "[$ns] admin password (save this now, it will not be shown again): $DefaultAdminPassword"
    }
}

foreach ($ns in $Namespaces) {
    kubectl create configmap ai-soc-site-config `
        --namespace $ns `
        --from-literal="WAZUH_API_URL=https://$($HostIp):55000" `
        --from-literal="WAZUH_INDEXER_URL=https://$($HostIp):9200" `
        --from-literal="WAZUH_VERIFY_SSL=false" `
        --from-literal="LOCAL_LLM_BASE_URL=http://$($HostIp):8001/v1" `
        --from-literal="SHUFFLE_BASE_URL=http://$($HostIp):3443" `
        --dry-run=client -o yaml | kubectl apply -f -
}

Write-Host ""
Write-Host "Site config applied in namespaces: $($Namespaces -join ', ')."
