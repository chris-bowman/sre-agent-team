# scripts/deploy-escalation-proxy.ps1
# Deploys the Platform Escalation MCP Proxy as an Azure Container App.
# Run this AFTER deploy-platform.ps1. Platform team runs this ONCE.
#
# Prerequisites:
#   - az CLI with Docker or ACR build available
#   - Contributor on the platform resource group
#   - Application Administrator (Entra) to create app registration and app roles
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
    [string] $CallerPoliciesJson = '',
    [string] $McpAllowedHosts = '',
    [ValidateRange(1, 100)] [int] $MinReplicas = 1,
    [ValidateRange(1, 100)] [int] $MaxReplicas = 5,
    [ValidateRange(30, 730)] [int] $LogRetentionDays = 30,
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
if ([string]::IsNullOrWhiteSpace($PlatformAgentId) -or [string]::IsNullOrWhiteSpace($PlatformAgentEndpoint)) {
    throw 'PlatformAgentId and PlatformAgentEndpoint are required. Pass them explicitly or run deploy-platform.ps1 first so they are stored in deploy state.'
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

Write-Host "`n=== Step 2: Resolve Entra app registration for the proxy ===" -ForegroundColor Cyan
$tenantId = az account show --query tenantId -o tsv

$appDisplayName = "SRE Escalation Proxy ($ProxyAppName)"
$entraAppId = $ProxyEntraAppId
$entraObjectId = ''

if ([string]::IsNullOrWhiteSpace($entraAppId)) {
    $matchingApps = @(az ad app list --display-name $appDisplayName --query '[].{appId:appId,id:id}' -o json | ConvertFrom-Json)
    if ($matchingApps.Count -gt 1) {
        throw "Multiple Entra applications found with display name '$appDisplayName'. Pass -ProxyEntraAppId explicitly to select the stable registration."
    }
    if ($matchingApps.Count -eq 1) {
        $entraAppId = $matchingApps[0].appId
        $entraObjectId = $matchingApps[0].id
        Write-Host "Reusing existing Entra app: $entraAppId (object: $entraObjectId)"
    }
}

if ([string]::IsNullOrWhiteSpace($entraAppId)) {
    $appJson = az ad app create `
        --display-name $appDisplayName `
        --sign-in-audience 'AzureADMyOrg' `
        --output json | ConvertFrom-Json
    $entraAppId = $appJson.appId
    $entraObjectId = $appJson.id
    Write-Host "Entra app created: $entraAppId (object: $entraObjectId)"
} elseif ([string]::IsNullOrWhiteSpace($entraObjectId)) {
    $entraObjectId = az ad app show --id $entraAppId --query id -o tsv
    if ([string]::IsNullOrWhiteSpace($entraObjectId)) {
        throw "The supplied ProxyEntraAppId '$entraAppId' could not be resolved."
    }
    Write-Host "Using supplied Entra app: $entraAppId (object: $entraObjectId)"
}

Write-Host "`n=== Step 2a: Set Application ID URI for scope-based MI tokens ===" -ForegroundColor Cyan
az ad app update --id $entraObjectId --identifier-uris "api://$entraAppId" | Out-Null
Write-Host "Application ID URI set: api://$entraAppId"

Write-Host "`n=== Step 3: Add EscalationCaller app role to the registration ===" -ForegroundColor Cyan
$existingAppRoleId = az ad app show --id $entraAppId --query "appRoles[?value=='EscalationCaller'].id | [0]" -o tsv
if ([string]::IsNullOrWhiteSpace($existingAppRoleId)) {
    $appRoleManifest = @(
        @{
            allowedMemberTypes = @('Application')
            description        = 'Allows a workload SRE agent to escalate investigations to the platform agent'
            displayName        = 'EscalationCaller'
            id                 = [guid]::NewGuid().ToString()
            isEnabled          = $true
            value              = 'EscalationCaller'
        }
    ) | ConvertTo-Json -Compress

    # Write to a temp file (az CLI requires a file for app role manifest)
    $tmpFile = [System.IO.Path]::GetTempFileName() + '.json'
    $appRoleManifest | Out-File -FilePath $tmpFile -Encoding utf8
    az ad app update --id $entraObjectId --app-roles "@$tmpFile"
    Remove-Item $tmpFile
    Write-Host "EscalationCaller app role added"
} else {
    Write-Host "EscalationCaller app role already present"
}

Write-Host "`n=== Step 4: Create service principal for the app registration ===" -ForegroundColor Cyan
$spObjectId = az ad sp show --id $entraAppId --query id -o tsv 2>$null
if ([string]::IsNullOrWhiteSpace($spObjectId)) {
    az ad sp create --id $entraObjectId | Out-Null
    Write-Host "Service principal created"
} else {
    Write-Host "Service principal already exists"
}

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
    } else {
        Write-Host "NOTE: 'table' without -EnablePrivateNetworking requires public Storage network access. Some tenant policies force it off, which fails create/status/summary calls at runtime." -ForegroundColor Yellow
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
        entraAppClientId=$entraAppId `
        callerPoliciesJson=$CallerPoliciesJson `
        revisionSuffix=$revisionSuffix `
        sreAgentAdminRoleDefinitionId=$sreAgentAdminRoleId `
        storageTableDataContributorRoleDefinitionId=$storageTableRoleId `
        registryBackend=$RegistryBackend `
        minReplicas=$MinReplicas `
        maxReplicas=$MaxReplicas `
        logRetentionDays=$LogRetentionDays `
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
Set-DeployState -Key 'ProxyEntraClientId'  -Value $entraAppId
Set-DeployState -Key 'ProxyPrincipalId'    -Value $proxyPrincipalId
Set-DeployState -Key 'ProxySubscriptionId' -Value $SubscriptionId
Set-DeployState -Key 'ProxyResourceGroup'  -Value $ResourceGroup
Set-DeployState -Key 'ProxyAppName'        -Value $ProxyAppName
Set-DeployState -Key 'ProxyImageDigest'    -Value $imageDigest
Set-DeployState -Key 'ProxyImageReference' -Value $containerImage

Write-Host "Save these values for workload agent deployments (also stored in deploy state):"
Write-Host "  PROXY_ENDPOINT_URL:     $proxyEndpointUrl"
Write-Host "  PROXY_ENTRA_CLIENT_ID:  $entraAppId"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  - Deploy workload agents: scripts/deploy-workload.ps1"
Write-Host "  - For each workload agent, run: scripts/grant-workload-escalation.ps1"

return [ordered]@{
    ProxyEndpointUrl   = $proxyEndpointUrl
    ProxyEntraClientId = $entraAppId
    ProxyPrincipalId   = $proxyPrincipalId
    ProxyImageDigest   = $imageDigest
    ProxyImageReference = $containerImage
}
