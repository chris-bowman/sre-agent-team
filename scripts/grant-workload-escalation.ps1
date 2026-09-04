# scripts/grant-workload-escalation.ps1
# Platform team runs this to onboard each new workload agent.
# Grants the workload agent's managed identity the 'EscalationCaller' app role
# on the escalation proxy's Entra app registration.
#
# Prerequisites:
#   - Application Administrator or app owner role in Entra ID
#   - The workload agent must be deployed first (get principalId from deploy-workload output)

[CmdletBinding()]
param (
    # Optional: resolved from deploy state when omitted.
    [string] $WorkloadPrincipalId = '',  # Workload agent's MI object ID
    [string] $EntraAppId = '',           # Proxy's Entra app registration client ID
    [string] $WorkloadName = ''          # For logging
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

$WorkloadPrincipalId = Resolve-Value -Provided $WorkloadPrincipalId -StateKey 'WorkloadAgentUamiPrincipal'
if ([string]::IsNullOrWhiteSpace($WorkloadPrincipalId)) {
    # Backward compatibility with older state files that only stored system-assigned principal.
    $WorkloadPrincipalId = Resolve-Value -Provided '' -StateKey 'WorkloadAgentPrincipal'
}
$EntraAppId          = Resolve-Value -Provided $EntraAppId          -StateKey 'ProxyEntraClientId'
$systemAssignedPrincipalId = Resolve-Value -Provided '' -StateKey 'WorkloadAgentPrincipal'
if ([string]::IsNullOrWhiteSpace($WorkloadName)) {
    $WorkloadName = Resolve-Value -Provided '' -StateKey 'WorkloadAgentName'
    if ([string]::IsNullOrWhiteSpace($WorkloadName)) { $WorkloadName = 'unknown' }
}

if ([string]::IsNullOrWhiteSpace($WorkloadPrincipalId) -or [string]::IsNullOrWhiteSpace($EntraAppId)) {
    throw 'WorkloadPrincipalId and EntraAppId are required. Pass them explicitly or run deploy-workload.ps1 + deploy-escalation-proxy.ps1 first so they are stored in deploy state.'
}

Write-Host "=== Granting EscalationCaller app role ===" -ForegroundColor Cyan
Write-Host "  Workload:   $WorkloadName ($WorkloadPrincipalId)"
Write-Host "  Proxy App:  $EntraAppId"

# Look up the proxy's service principal object ID
$proxySPObjectId = az ad sp show --id $EntraAppId --query id -o tsv

# Look up the EscalationCaller app role ID on the application object.
# If missing, create it so this script can recover from partial proxy setup.
$appRoleId = az ad app show --id $EntraAppId `
    --query "appRoles[?value=='EscalationCaller'].id | [0]" `
    -o tsv

if ([string]::IsNullOrWhiteSpace($appRoleId)) {
    Write-Host "  EscalationCaller app role missing. Creating it on app $EntraAppId..." -ForegroundColor Yellow

    $existingAppRolesJson = az ad app show --id $EntraAppId --query "appRoles" -o json
    $existingAppRoles = @()
    if (-not [string]::IsNullOrWhiteSpace($existingAppRolesJson)) {
        $parsedRoles = $existingAppRolesJson | ConvertFrom-Json
        if ($null -ne $parsedRoles) { $existingAppRoles = @($parsedRoles) }
    }

    $existingAppRoles += [pscustomobject]@{
        allowedMemberTypes = @('Application')
        description        = 'Allows a workload SRE agent to escalate investigations to the platform agent'
        displayName        = 'EscalationCaller'
        id                 = [guid]::NewGuid().ToString()
        isEnabled          = $true
        value              = 'EscalationCaller'
    }

    $appObjectId = az ad app show --id $EntraAppId --query id -o tsv
    $tmpPatchFile = [System.IO.Path]::GetTempFileName() + '.json'
    (@{ appRoles = $existingAppRoles } | ConvertTo-Json -Depth 20) | Out-File -FilePath $tmpPatchFile -Encoding utf8
    az rest `
        --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" `
        --headers "Content-Type=application/json" `
        --body "@$tmpPatchFile" | Out-Null
    Remove-Item $tmpPatchFile -Force

    Start-Sleep -Seconds 5
    $appRoleId = az ad app show --id $EntraAppId `
        --query "appRoles[?value=='EscalationCaller'].id | [0]" `
        -o tsv
}

if ([string]::IsNullOrWhiteSpace($appRoleId)) {
    throw "EscalationCaller app role not found on app $EntraAppId even after attempting to create it."
}

Write-Host "  App Role ID: $appRoleId"

"`nEnsuring EscalationCaller on workload identities..." | Write-Host
$principalIds = @($WorkloadPrincipalId, $systemAssignedPrincipalId) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
foreach ($principalId in $principalIds) {
    # Use file-based JSON to avoid PowerShell quoting/encoding issues.
    $tmpAssignFile = [System.IO.Path]::GetTempFileName() + '.json'
    (@{ principalId = $principalId; resourceId = $proxySPObjectId; appRoleId = $appRoleId } | ConvertTo-Json -Depth 5) | Out-File -FilePath $tmpAssignFile -Encoding utf8

    $existingAssignmentCount = az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$proxySPObjectId/appRoleAssignedTo" --query "value[?principalId=='$principalId' && appRoleId=='$appRoleId'] | length(@)" -o tsv
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $tmpAssignFile -Force
        throw 'Failed to query existing app-role assignments from Microsoft Graph.'
    }

    if ($existingAssignmentCount -eq '0') {
        az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$proxySPObjectId/appRoleAssignedTo" --headers "Content-Type=application/json" --body "@$tmpAssignFile" | Out-Null
        $postExit = $LASTEXITCODE
        if ($postExit -ne 0) {
            Remove-Item $tmpAssignFile -Force
            throw "Failed to create app-role assignment for principal $principalId."
        }
        Write-Host "  Granted to $principalId" -ForegroundColor Green
    } else {
        Write-Host "  Already assigned to $principalId" -ForegroundColor Yellow
    }
    Remove-Item $tmpAssignFile -Force
}
Write-Host "`nApp role grants verified successfully." -ForegroundColor Green
Write-Host "Workload agent '$WorkloadName' can now escalate to the Platform SRE Agent via the proxy."
Write-Host ""
Write-Host "Test: In the workload SRE Agent portal, type: /agent platform-escalation"
Write-Host "Then: 'Test the escalation path by creating a dummy investigation.'"
