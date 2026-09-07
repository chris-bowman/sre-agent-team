# One-time Microsoft Entra bootstrap for the Platform Escalation Proxy.

[CmdletBinding()]
param (
    [string] $ProxyAppName = 'sre-escalation-proxy',
    [string] $ProxyEntraAppId = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

$appDisplayName = "SRE Escalation Proxy ($ProxyAppName)"
$entraAppId = $ProxyEntraAppId
$entraObjectId = ''

if ([string]::IsNullOrWhiteSpace($entraAppId)) {
    $matchingApps = @(az ad app list --display-name $appDisplayName --query '[].{appId:appId,id:id}' --output json | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to query Microsoft Entra applications. Refresh Azure CLI authentication and retry.'
    }
    if ($matchingApps.Count -gt 1) {
        throw "Multiple Entra applications found with display name '$appDisplayName'. Pass -ProxyEntraAppId explicitly."
    }
    if ($matchingApps.Count -eq 1) {
        $entraAppId = $matchingApps[0].appId
        $entraObjectId = $matchingApps[0].id
        Write-Host "Reusing existing Entra app: $entraAppId"
    }
}

if ([string]::IsNullOrWhiteSpace($entraAppId)) {
    $appJson = az ad app create `
        --display-name $appDisplayName `
        --sign-in-audience AzureADMyOrg `
        --output json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $null -eq $appJson) {
        throw 'Failed to create the proxy Microsoft Entra application.'
    }
    $entraAppId = $appJson.appId
    $entraObjectId = $appJson.id
    Write-Host "Entra app created: $entraAppId"
} elseif ([string]::IsNullOrWhiteSpace($entraObjectId)) {
    $entraObjectId = az ad app show --id $entraAppId --query id --output tsv
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($entraObjectId)) {
        throw "The supplied ProxyEntraAppId '$entraAppId' could not be resolved."
    }
    Write-Host "Using supplied Entra app: $entraAppId"
}

$identifierUrisJson = az ad app show --id $entraAppId --query identifierUris --output json
if ($LASTEXITCODE -ne 0) { throw 'Failed to inspect the proxy Application ID URIs.' }
$identifierUris = @($identifierUrisJson | ConvertFrom-Json)
$requiredIdentifierUri = "api://$entraAppId"
if ($identifierUris -notcontains $requiredIdentifierUri) {
    $identifierUris += $requiredIdentifierUri
    az ad app update --id $entraObjectId --identifier-uris $identifierUris --output none
    if ($LASTEXITCODE -ne 0) { throw 'Failed to configure the proxy Application ID URI.' }
}

$existingAppRolesJson = az ad app show --id $entraAppId --query appRoles --output json
if ($LASTEXITCODE -ne 0) { throw 'Failed to inspect the proxy application roles.' }
$existingAppRoles = @($existingAppRolesJson | ConvertFrom-Json)
$escalationCallerRole = @($existingAppRoles | Where-Object { $_.value -eq 'EscalationCaller' })
if ($escalationCallerRole.Count -gt 1) {
    throw 'The proxy application has multiple EscalationCaller roles. Resolve the duplicate role definitions before retrying.'
}
if ($escalationCallerRole.Count -eq 1) {
    if (-not $escalationCallerRole[0].isEnabled -or $escalationCallerRole[0].allowedMemberTypes -notcontains 'Application') {
        throw 'The existing EscalationCaller role must be enabled and allow Application members.'
    }
} else {
    $appRoleManifest = @($existingAppRoles) + @(
        @{
            allowedMemberTypes = @('Application')
            description        = 'Allows an approved same-tenant caller to request platform investigations'
            displayName        = 'EscalationCaller'
            id                 = [guid]::NewGuid().ToString()
            isEnabled          = $true
            value              = 'EscalationCaller'
        }
    ) | ConvertTo-Json -Depth 10 -Compress
    $temporaryFile = [System.IO.Path]::GetTempFileName() + '.json'
    try {
        [System.IO.File]::WriteAllText($temporaryFile, $appRoleManifest, (New-Object System.Text.UTF8Encoding($false)))
        az ad app update --id $entraObjectId --app-roles "@$temporaryFile" --output none
        if ($LASTEXITCODE -ne 0) { throw 'Failed to add the EscalationCaller application role.' }
    } finally {
        Remove-Item $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

$servicePrincipalId = az ad sp show --id $entraAppId --query id --output tsv 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($servicePrincipalId)) {
    az ad sp create --id $entraAppId --output none
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create the proxy service principal.' }
}

Set-DeployState -Key 'ProxyEntraClientId' -Value $entraAppId

Write-Host 'Microsoft Entra bootstrap complete.' -ForegroundColor Green
Write-Host "  Proxy application client ID: $entraAppId"

return [ordered]@{
    ProxyEntraClientId = $entraAppId
}