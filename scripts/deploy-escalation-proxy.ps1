# scripts/deploy-escalation-proxy.ps1
# Deploys the Platform Escalation MCP Proxy as an Azure Container App.
# Run this AFTER deploy-platform.ps1 and initialize-escalation-proxy-entra.ps1.
#
# Prerequisites:
#   - az CLI with Docker or ACR build available
#   - Contributor on the platform resource group
#   - Existing proxy Entra application client ID from bootstrap or explicit input
#   - Values from deploy-platform.ps1 output

[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $SubscriptionId,
    # Optional: resolved from deploy state (deploy-platform.ps1) when omitted.
    [string] $PlatformAgentId = '',        # From deploy-platform output
    [string] $PlatformAgentEndpoint = '',  # From deploy-platform output
    [Parameter(Mandatory)] [string] $AcrName,                # Azure Container Registry name
    [string] $ProxyAppName = 'sre-escalation-proxy',
    [string] $Location = 'australiaeast',
    [string] $ImageTag = '',
    [string] $PipIndexUrl = 'https://packagefeedproxy.microsoft.io/pypi/simple/',
    [string] $ProxyEntraAppId = '',
    [switch] $BootstrapEntraApplication,
    [string] $CallerPoliciesJson = '',
    [string] $AppConfigurationName = '',
    [string] $CallerPolicyKey = 'escalation/caller-policies',
    [string] $CallerPolicyLabel = 'production',
    [ValidateRange(1, 3600)] [int] $CallerPolicyRefreshSeconds = 30,
    [ValidateRange(1, 86400)] [int] $CallerPolicyMaxStalenessSeconds = 300,
    [ValidateRange(60, 1800)] [int] $AppConfigurationRbacTimeoutSeconds = 600,
    [string] $McpAllowedHosts = '',
    [ValidateRange(1, 100)] [int] $MinReplicas = 1,
    [ValidateRange(1, 100)] [int] $MaxReplicas = 5,
    [ValidateRange(30, 730)] [int] $LogRetentionDays = 30,
    [ValidateRange(1, 365)] [int] $ActiveMetadataRetentionDays = 1,
    [ValidateRange(1, 365)] [int] $FinalFindingsMetadataRetentionDays = 7,
    [ValidateRange(1, 86400)] [int] $ExpiryCleanupIntervalSeconds = 300,
    [ValidateRange(1, 100)] [int] $MaxConcurrentBlockingSdkCalls = 16,
    [ValidateRange(1, 100)] [int] $MaxConcurrentPlatformRequests = 16,
    [ValidateRange(0.01, 30)] [double] $PlatformRequestQueueTimeoutSeconds = 0.25,
    [ValidateRange(0, 60)] [int] $ReadinessCacheSeconds = 5,
    [ValidateRange(1, 60)] [int] $ReadinessTimeoutSeconds = 15,
    [ValidateRange(2, 120)] [int] $ReadinessProbeTimeoutSeconds = 20,
    [ValidateRange(1024, 10485760)] [int] $MaxPlatformResponseBytes = 1048576,
    [ValidateRange(1, 1000)] [int] $MaxAgentMessages = 100,
    [ValidateRange(1, 3600)] [int] $MinSummaryPollIntervalSeconds = 5,
    [ValidateRange(1, 10000)] [int] $MaxSummaryPollsPerInvestigation = 288,
    [ValidateSet('table', 'memory')] [string] $RegistryBackend = 'table',
    [switch] $EnablePrivateNetworking,
    [string] $PrivateNetworkName = '',
    [string] $PrivateNetworkAddressPrefix = '10.42.0.0/16',
    [string] $ContainerEnvironmentSubnetPrefix = '10.42.0.0/27',
    [string] $StoragePrivateEndpointSubnetPrefix = '10.42.1.0/28'
    ,[ValidateSet('true', 'false')] [string] $McpEnableDnsRebindingProtection = 'true'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Shared helpers: state file + SRE Agent Administrator role resolution.
. "$PSScriptRoot\common.ps1"

# Resolve platform agent details from deploy state when not passed explicitly.
$PlatformAgentId       = Resolve-Value -Provided $PlatformAgentId       -StateKey 'PlatformAgentId'
$PlatformAgentEndpoint = Resolve-Value -Provided $PlatformAgentEndpoint -StateKey 'PlatformAgentEndpoint'
$ProxyEntraAppId       = Resolve-Value -Provided $ProxyEntraAppId       -StateKey 'ProxyEntraClientId'
if ([string]::IsNullOrWhiteSpace($PlatformAgentId) -or [string]::IsNullOrWhiteSpace($PlatformAgentEndpoint)) {
    throw 'PlatformAgentId and PlatformAgentEndpoint are required. Pass them explicitly or run deploy-platform.ps1 first so they are stored in deploy state.'
}
if ([string]::IsNullOrWhiteSpace($ProxyEntraAppId) -and $BootstrapEntraApplication) {
    Write-Host 'No proxy Entra client ID was found; running the privileged bootstrap.' -ForegroundColor Yellow
    $bootstrapResult = & "$PSScriptRoot\initialize-escalation-proxy-entra.ps1" -ProxyAppName $ProxyAppName
    $ProxyEntraAppId = [string]$bootstrapResult.ProxyEntraClientId
}
if ([string]::IsNullOrWhiteSpace($ProxyEntraAppId)) {
    throw 'ProxyEntraAppId is required. Pass an existing client ID, run initialize-escalation-proxy-entra.ps1 first, or explicitly opt in with -BootstrapEntraApplication.'
}
$parsedProxyEntraAppId = [guid]::Empty
if (-not [guid]::TryParse($ProxyEntraAppId, [ref]$parsedProxyEntraAppId)) {
    throw "ProxyEntraAppId '$ProxyEntraAppId' is not a valid application client ID."
}

if ([string]::IsNullOrWhiteSpace($ImageTag)) {
    $ImageTag = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
}
if ($ImageTag -eq 'latest') {
    throw 'ImageTag must be an immutable release tag; latest is not supported.'
}
if ($MaxReplicas -lt $MinReplicas) {
    throw 'MaxReplicas must be greater than or equal to MinReplicas.'
}
if ($CallerPolicyMaxStalenessSeconds -lt $CallerPolicyRefreshSeconds) {
    throw 'CallerPolicyMaxStalenessSeconds must be greater than or equal to CallerPolicyRefreshSeconds.'
}
if ($RegistryBackend -eq 'table' -and -not $EnablePrivateNetworking) {
    throw "Table registry deployments require -EnablePrivateNetworking. Use -RegistryBackend memory for local or non-production smoke tests."
}
if ($ReadinessProbeTimeoutSeconds -le $ReadinessTimeoutSeconds) {
    throw 'ReadinessProbeTimeoutSeconds must be greater than ReadinessTimeoutSeconds.'
}
if ([string]::IsNullOrWhiteSpace($AppConfigurationName)) {
    $subscriptionPrefix = $SubscriptionId.Replace('-', '').Substring(0, 8)
    $AppConfigurationName = "${ProxyAppName}-${subscriptionPrefix}-config"
    if ($AppConfigurationName.Length -gt 50) {
        $AppConfigurationName = $AppConfigurationName.Substring(0, 50).TrimEnd('-')
    }
}

$existingRevision = az containerapp show `
    --name $ProxyAppName `
    --resource-group $ResourceGroup `
    --subscription $SubscriptionId `
    --query properties.latestReadyRevisionName `
    --output tsv 2>$null
if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($existingRevision)) {
    $existingRevisionActive = az containerapp revision show `
        --name $ProxyAppName `
        --resource-group $ResourceGroup `
        --subscription $SubscriptionId `
        --revision $existingRevision `
        --query properties.active `
        --output tsv
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to inspect existing proxy revision '$existingRevision'."
    }
    if ($existingRevisionActive -ne 'true') {
        throw "Existing proxy revision '$existingRevision' is inactive. Reactivate it before deployment so a pre-ARM failure cannot leave the service at zero replicas."
    }
}

$taggedImageName = "$AcrName.azurecr.io/${ProxyAppName}:$ImageTag"
$revisionSuffix = (Get-Date).ToUniversalTime().ToString('yyMMddHHmmss')
$privateNetworkingValue = if ($EnablePrivateNetworking.IsPresent) { 'true' } else { 'false' }

Write-Host "=== Step 1: Build and push container image ===" -ForegroundColor Cyan
$previousPythonIoEncoding = $env:PYTHONIOENCODING
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    $env:PYTHONIOENCODING = 'utf-8'
    $env:PYTHONUTF8 = '1'
    Push-Location "$PSScriptRoot\..\escalation-proxy\app"
    try {
        az acr build `
            --registry $AcrName `
            --image "${ProxyAppName}:$ImageTag" `
            --build-arg "PIP_INDEX_URL=$PipIndexUrl" `
            --no-logs `
            .
        if ($LASTEXITCODE -ne 0) {
            throw "ACR build failed for image '$taggedImageName'."
        }
    } finally {
        Pop-Location
    }
} finally {
    $env:PYTHONIOENCODING = $previousPythonIoEncoding
    $env:PYTHONUTF8 = $previousPythonUtf8
}
Write-Host "Image pushed: $taggedImageName"

# Get ACR login server for Container App registries config
$acrLoginServer = az acr show --name $AcrName --subscription $SubscriptionId --query "loginServer" -o tsv
$acrResourceId = az acr show --name $AcrName --subscription $SubscriptionId --query "id" -o tsv
Write-Host "ACR login server: $acrLoginServer"

$imageDigest = az acr manifest show-metadata `
    --registry $AcrName `
    --name "${ProxyAppName}:$ImageTag" `
    --query digest `
    --output tsv
if ($LASTEXITCODE -ne 0 -or $imageDigest -notmatch '^sha256:[0-9a-f]{64}$') {
    throw "Could not resolve a valid sha256 digest for image '$taggedImageName'."
}
$containerImage = "$acrLoginServer/${ProxyAppName}@$imageDigest"
Write-Host "Immutable image reference: $containerImage"

Write-Host "`n=== Step 2: Use bootstrapped Entra application ===" -ForegroundColor Cyan
$tenantId = az account show --query tenantId -o tsv
Write-Host "Using proxy Entra application client ID: $ProxyEntraAppId"

Write-Host "`n=== Step 5: Set active subscription ===" -ForegroundColor Cyan
az account set --subscription $SubscriptionId

Write-Host "`n=== Step 5a: Ensure proxy identity has AcrPull on ACR ===" -ForegroundColor Cyan
$uamiName = "$ProxyAppName-id"
$uamiExists = $false
try {
    $null = az identity show --resource-group $ResourceGroup --name $uamiName --query id -o tsv 2>$null
    $uamiExists = ($LASTEXITCODE -eq 0)
} catch {
    $uamiExists = $false
}

if (-not $uamiExists) {
    az identity create --resource-group $ResourceGroup --name $uamiName --location $Location | Out-Null
}

$proxyUamiPrincipalId = az identity show --resource-group $ResourceGroup --name $uamiName --query principalId -o tsv
$acrPullCount = az role assignment list `
    --assignee-object-id $proxyUamiPrincipalId `
    --scope $acrResourceId `
    --query "[?roleDefinitionName=='AcrPull'] | length(@)" `
    -o tsv

if ($acrPullCount -eq '0') {
    az role assignment create `
        --assignee-object-id $proxyUamiPrincipalId `
        --assignee-principal-type ServicePrincipal `
        --role AcrPull `
        --scope $acrResourceId | Out-Null
    Start-Sleep -Seconds 15
}

Write-Host "`n=== Step 5b: Resolve SRE Agent Administrator role definition ===" -ForegroundColor Cyan
$sreAgentAdminRoleId = Get-SreAgentAdministratorRoleId
Write-Host "SRE Agent Administrator role ID: $sreAgentAdminRoleId"

Write-Host "`n=== Step 5c: Resolve Storage Table Data Contributor role definition ===" -ForegroundColor Cyan
$storageTableRoleId = ''
if ($RegistryBackend -eq 'table') {
    $storageTableRoleId = az role definition list --name "Storage Table Data Contributor" --query "[0].name" -o tsv
    if ([string]::IsNullOrWhiteSpace($storageTableRoleId)) {
        throw 'Could not resolve the Storage Table Data Contributor role definition.'
    }
    Write-Host "Storage Table Data Contributor role ID: $storageTableRoleId"
} else {
    Write-Host 'Storage Table role resolution skipped for memory backend.'
}

if ($RegistryBackend -eq 'table') {
    if ($EnablePrivateNetworking) {
        if ([string]::IsNullOrWhiteSpace($PrivateNetworkName)) {
            $PrivateNetworkName = "${ProxyAppName}-vnet"
        }
        Write-Host "Private networking enabled: Container Apps VNet integration, Storage Table private endpoint, and private DNS will be deployed." -ForegroundColor Green
    }
}

Write-Host "`n=== Step 6: Deploy escalation proxy Container App ===" -ForegroundColor Cyan
if ([string]::IsNullOrWhiteSpace($CallerPoliciesJson)) {
    $existingCallerPolicies = az containerapp list `
        --resource-group $ResourceGroup `
        --subscription $SubscriptionId `
        --query "[?name=='$ProxyAppName'] | [0].properties.template.containers[0].env[?name=='CALLER_POLICIES_JSON'].value | [0]" `
        --output tsv 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to inspect the existing proxy caller policy before deployment.'
    }
    if (-not [string]::IsNullOrWhiteSpace($existingCallerPolicies)) {
        $CallerPoliciesJson = $existingCallerPolicies
        Write-Host 'Preserving existing caller policy configuration.' -ForegroundColor Green
    }
}
$callerPoliciesParameterValue = $CallerPoliciesJson.Replace('"', '\"')

if ([string]::IsNullOrWhiteSpace($CallerPoliciesJson)) { $CallerPoliciesJson = '[]' }

Write-Host "`n=== Step 5d: Seed dynamic caller policy in App Configuration ===" -ForegroundColor Cyan
$appConfiguration = az appconfig show `
    --name $AppConfigurationName `
    --resource-group $ResourceGroup `
    --subscription $SubscriptionId `
    --output json 2>$null
if ($LASTEXITCODE -ne 0) {
    az appconfig create `
        --name $AppConfigurationName `
        --resource-group $ResourceGroup `
        --subscription $SubscriptionId `
        --location $Location `
        --sku Free `
        --disable-local-auth true `
        --output none
    if ($LASTEXITCODE -ne 0) { throw "Failed to create App Configuration store '$AppConfigurationName'." }
}

$appConfigurationId = az appconfig show `
    --name $AppConfigurationName `
    --resource-group $ResourceGroup `
    --subscription $SubscriptionId `
    --query id `
    --output tsv
$appConfigurationEndpoint = az appconfig show `
    --name $AppConfigurationName `
    --resource-group $ResourceGroup `
    --subscription $SubscriptionId `
    --query endpoint `
    --output tsv
az resource update `
    --ids $appConfigurationId `
    --api-version 2024-05-01 `
    --set properties.disableLocalAuth=true properties.dataPlaneProxy.authenticationMode=Pass-through properties.dataPlaneProxy.privateLinkDelegation=Disabled `
    --output none
if ($LASTEXITCODE -ne 0) { throw 'Failed to enforce App Configuration authentication settings.' }

$armAccessToken = az account get-access-token `
    --resource https://management.azure.com/ `
    --query accessToken `
    --output tsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($armAccessToken)) {
    throw 'Could not obtain an Azure Resource Manager token for App Configuration policy administration.'
}
$tokenPayload = $armAccessToken.Split('.')[1].Replace('-', '+').Replace('_', '/')
while ($tokenPayload.Length % 4 -ne 0) { $tokenPayload += '=' }
$tokenClaims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($tokenPayload)) | ConvertFrom-Json
$signedInPrincipalId = [string]$tokenClaims.oid
if ([string]::IsNullOrWhiteSpace($signedInPrincipalId)) {
    throw 'The Azure Resource Manager token does not contain an oid claim for App Configuration policy administration.'
}
$signedInPrincipalType = if ($tokenClaims.idtyp -eq 'app') { 'ServicePrincipal' } else { 'User' }
$dataOwnerRoleId = '5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b'
$dataOwnerAssignmentsJson = az role assignment list `
    --assignee-object-id $signedInPrincipalId `
    --scope $appConfigurationId `
    --role $dataOwnerRoleId `
    --output json
if ($LASTEXITCODE -ne 0) { throw 'Failed to inspect App Configuration Data Owner assignments.' }
$dataOwnerAssignmentCount = @($dataOwnerAssignmentsJson | ConvertFrom-Json).Count
if ($dataOwnerAssignmentCount -eq 0) {
    az role assignment create `
        --assignee-object-id $signedInPrincipalId `
        --assignee-principal-type $signedInPrincipalType `
        --role $dataOwnerRoleId `
        --scope $appConfigurationId `
        --output none
    if ($LASTEXITCODE -ne 0) { throw 'Failed to grant App Configuration Data Owner to the signed-in operator.' }
}

$policySeeded = $false
$policySeedDeadline = [DateTimeOffset]::UtcNow.AddSeconds($AppConfigurationRbacTimeoutSeconds)
$attempt = 0
while (-not $policySeeded) {
    $attempt++
    try {
        $existingPolicySetting = Get-AppConfigurationSetting `
            -Endpoint $appConfigurationEndpoint `
            -Key $CallerPolicyKey `
            -Label $CallerPolicyLabel `
            -AllowNotFound
        if ($null -eq $existingPolicySetting) {
            $null = Set-AppConfigurationSetting `
                -Endpoint $appConfigurationEndpoint `
                -Key $CallerPolicyKey `
                -Label $CallerPolicyLabel `
                -Value $CallerPoliciesJson `
                -Tags @{ operation = 'deployment-migration' }
            Write-Host 'Seeded caller policy in App Configuration.' -ForegroundColor Green
        } else {
            Write-Host 'Preserving existing caller policy in App Configuration.' -ForegroundColor Green
        }
        $policySeeded = $true
    } catch {
        $remainingSeconds = [math]::Floor(($policySeedDeadline - [DateTimeOffset]::UtcNow).TotalSeconds)
        if ($remainingSeconds -le 0) {
            throw "App Configuration data-plane access did not become ready within $AppConfigurationRbacTimeoutSeconds seconds. The active Container App revision was left unchanged."
        }
        $retrySeconds = [math]::Min([math]::Min([math]::Pow(2, [math]::Min($attempt, 5)), 30), $remainingSeconds)
        Write-Warning "App Configuration data-plane access is not ready; retrying in $retrySeconds seconds (up to $remainingSeconds seconds remaining)."
        Start-Sleep -Seconds $retrySeconds
    }
}

$deployOutputJson = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file "$PSScriptRoot\..\escalation-proxy\infrastructure\main.bicep" `
    --parameters `
        proxyAppName=$ProxyAppName `
        location=$Location `
        containerImage=$containerImage `
        platformAgentResourceId=$PlatformAgentId `
        platformAgentEndpoint=$PlatformAgentEndpoint `
        tenantId=$tenantId `
        entraAppClientId=$ProxyEntraAppId `
        callerPoliciesJson=$callerPoliciesParameterValue `
        appConfigurationName=$AppConfigurationName `
        callerPolicyKey=$CallerPolicyKey `
        callerPolicyLabel=$CallerPolicyLabel `
        callerPolicyRefreshSeconds=$CallerPolicyRefreshSeconds `
        callerPolicyMaxStalenessSeconds=$CallerPolicyMaxStalenessSeconds `
        revisionSuffix=$revisionSuffix `
        sreAgentAdminRoleDefinitionId=$sreAgentAdminRoleId `
        storageTableDataContributorRoleDefinitionId=$storageTableRoleId `
        registryBackend=$RegistryBackend `
        minReplicas=$MinReplicas `
        maxReplicas=$MaxReplicas `
        logRetentionDays=$LogRetentionDays `
        activeMetadataRetentionDays=$ActiveMetadataRetentionDays `
        finalFindingsMetadataRetentionDays=$FinalFindingsMetadataRetentionDays `
        expiryCleanupIntervalSeconds=$ExpiryCleanupIntervalSeconds `
        maxConcurrentBlockingSdkCalls=$MaxConcurrentBlockingSdkCalls `
        maxConcurrentPlatformRequests=$MaxConcurrentPlatformRequests `
        platformRequestQueueTimeoutSeconds=$($PlatformRequestQueueTimeoutSeconds.ToString([System.Globalization.CultureInfo]::InvariantCulture)) `
        readinessCacheSeconds=$ReadinessCacheSeconds `
        readinessTimeoutSeconds=$ReadinessTimeoutSeconds `
        readinessProbeTimeoutSeconds=$ReadinessProbeTimeoutSeconds `
        maxPlatformResponseBytes=$MaxPlatformResponseBytes `
        maxAgentMessages=$MaxAgentMessages `
        minSummaryPollIntervalSeconds=$MinSummaryPollIntervalSeconds `
        maxSummaryPollsPerInvestigation=$MaxSummaryPollsPerInvestigation `
        "enablePrivateNetworking=$privateNetworkingValue" `
        privateNetworkName=$PrivateNetworkName `
        privateNetworkAddressPrefix=$PrivateNetworkAddressPrefix `
        containerEnvironmentSubnetPrefix=$ContainerEnvironmentSubnetPrefix `
        storagePrivateEndpointSubnetPrefix=$StoragePrivateEndpointSubnetPrefix `
        "mcpEnableDnsRebindingProtection=$McpEnableDnsRebindingProtection" `
        acrLoginServer=$acrLoginServer `
    --query 'properties.outputs' `
    --output json
if ($LASTEXITCODE -ne 0) {
    throw 'Escalation proxy ARM deployment failed. Review the Azure deployment error above.'
}
$deployOutput = $deployOutputJson | ConvertFrom-Json
if ($null -eq $deployOutput) {
    throw 'Escalation proxy ARM deployment completed without returning expected outputs.'
}

$proxyEndpointUrl  = $deployOutput.proxyEndpointUrl.value
$proxyPrincipalId  = $deployOutput.proxyPrincipalId.value
$appConfigurationEndpoint = $deployOutput.appConfigurationEndpoint.value

$proxyHost = ([uri]$proxyEndpointUrl).Host
if ([string]::IsNullOrWhiteSpace($McpAllowedHosts)) {
    $McpAllowedHosts = "${proxyHost},${proxyHost}:*,localhost:*,127.0.0.1:*"
}

Write-Host "`n=== Step 6a: Configure MCP host allowlist ===" -ForegroundColor Cyan
az containerapp update `
    --name $ProxyAppName `
    --resource-group $ResourceGroup `
    --set-env-vars "MCP_ALLOWED_HOSTS=$McpAllowedHosts" | Out-Null
Write-Host "MCP allowed hosts configured: $McpAllowedHosts"

Write-Host "Escalation proxy deployed."
Write-Host "  Proxy endpoint:    $proxyEndpointUrl"
Write-Host "  Proxy principal:   $proxyPrincipalId"
Write-Host "  Registry backend: $RegistryBackend"

Write-Host "`n=== Step 7: Verify proxy endpoint is reachable ===" -ForegroundColor Cyan
$healthUrl = $proxyEndpointUrl -replace '/mcp$', '/health'
try {
    $resp = Invoke-WebRequest -Uri $healthUrl -TimeoutSec 15 -UseBasicParsing
    Write-Host "Proxy health check: $($resp.StatusCode)" -ForegroundColor Green
} catch {
    Write-Warning "Health check failed (proxy may still be starting): $($_.Exception.Message)"
}

Write-Host "`n=== Deployment complete ===" -ForegroundColor Green

# Persist outputs so deploy-workload.ps1 / grant-workload-escalation.ps1 / deploy-all.ps1 can read them.
Set-DeployState -Key 'ProxyEndpointUrl'    -Value $proxyEndpointUrl
Set-DeployState -Key 'ProxyEntraClientId'  -Value $ProxyEntraAppId
Set-DeployState -Key 'ProxyPrincipalId'    -Value $proxyPrincipalId
Set-DeployState -Key 'ProxySubscriptionId' -Value $SubscriptionId
Set-DeployState -Key 'ProxyResourceGroup'  -Value $ResourceGroup
Set-DeployState -Key 'ProxyAppName'        -Value $ProxyAppName
Set-DeployState -Key 'ProxyImageDigest'    -Value $imageDigest
Set-DeployState -Key 'ProxyImageReference' -Value $containerImage
Set-DeployState -Key 'AppConfigurationName' -Value $AppConfigurationName
Set-DeployState -Key 'AppConfigurationEndpoint' -Value $appConfigurationEndpoint

Write-Host "Save these values for workload agent deployments (also stored in deploy state):"
Write-Host "  PROXY_ENDPOINT_URL:     $proxyEndpointUrl"
Write-Host "  PROXY_ENTRA_CLIENT_ID:  $ProxyEntraAppId"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  - Deploy workload agents: scripts/deploy-workload.ps1"
Write-Host "  - For each workload agent, run: scripts/grant-workload-escalation.ps1"

return [ordered]@{
    ProxyEndpointUrl   = $proxyEndpointUrl
    ProxyEntraClientId = $ProxyEntraAppId
    ProxyPrincipalId   = $proxyPrincipalId
    ProxyImageDigest   = $imageDigest
    ProxyImageReference = $containerImage
}
