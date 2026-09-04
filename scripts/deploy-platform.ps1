# scripts/deploy-platform.ps1
# Deploy the Platform SRE Agent into the platform team's Azure scope.
# Run this ONCE as the platform team, before deploying workload agents or the escalation proxy.
#
# Prerequisites:
#   - az CLI >= 2.55 with az account set --subscription <platform-sub-id>
#   - Contributor + User Access Administrator on the platform resource group
#   - If using a management group, access to create MG-scoped role assignments
#   - SRE Agent resource provider registered: az provider register -n Microsoft.App

[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [string] $PlatformManagementGroupId = '',
    [string] $AgentName = 'sre-platform',
    [string] $Location = 'australiaeast',
    [switch] $EnableApplicationInsights,
    [switch] $SkipCustomAgentUpload,
    [switch] $SkipCurrentCallerAgentAdminAssignment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Shared helpers: state file, robust custom-agent upload, RBAC + endpoint resolution.
. "$PSScriptRoot\common.ps1"

Write-Host "=== Step 1: Set active subscription ===" -ForegroundColor Cyan
az account set --subscription $SubscriptionId
Write-Host "Subscription: $SubscriptionId"

Write-Host "`n=== Step 2: Ensure resource group exists ===" -ForegroundColor Cyan
az group create --name $ResourceGroup --location $Location --output table

Write-Host "`n=== Step 3: Register SRE Agent resource provider (idempotent) ===" -ForegroundColor Cyan
az provider register --namespace 'Microsoft.App' --wait
Write-Host "Microsoft.App registered"

Write-Host "`n=== Step 4: Deploy platform SRE Agent ===" -ForegroundColor Cyan
$deployOutput = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file "$PSScriptRoot\..\platform\main.bicep" `
    --parameters "$PSScriptRoot\..\platform\main.bicepparam" `
    --parameters agentName=$AgentName `
    --parameters location=$Location `
    --parameters enableApplicationInsights=$($EnableApplicationInsights.IsPresent) `
    --parameters platformManagementGroupId=$PlatformManagementGroupId `
    --query 'properties.outputs' `
    --output json | ConvertFrom-Json

$agentPrincipalId = $deployOutput.principalId.value
$agentUamiPrincipalId = $deployOutput.uamiPrincipalId.value
$agentEndpoint    = $deployOutput.agentEndpoint.value
$agentId          = $deployOutput.agentId.value
$appInsightsId    = if ($deployOutput.PSObject.Properties.Name -contains 'applicationInsightsId') { $deployOutput.applicationInsightsId.value } else { '' }

# The agentEndpoint property is only populated once the agent finishes provisioning.
# Resolve-AgentEndpoint returns the deployment output when present, else polls ARM.
$agentEndpoint = Resolve-AgentEndpoint `
    -SubscriptionId $SubscriptionId `
    -ResourceGroup $ResourceGroup `
    -AgentName $AgentName `
    -FromDeploymentOutput $agentEndpoint

Write-Host "Platform agent deployed."
Write-Host "  Agent ID:       $agentId"
Write-Host "  Endpoint:       $agentEndpoint"
Write-Host "  Principal ID:   $agentPrincipalId"
Write-Host "  UAMI Principal: $agentUamiPrincipalId"
if (-not [string]::IsNullOrWhiteSpace($appInsightsId)) {
    Write-Host "  App Insights:   $appInsightsId"
}

Write-Host "`n=== Step 5: Ensure current caller can use/manage this SRE Agent ===" -ForegroundColor Cyan
if ($SkipCurrentCallerAgentAdminAssignment) {
    Write-Host 'Skipping current-caller SRE Agent Administrator assignment (-SkipCurrentCallerAgentAdminAssignment set).'
} else {
    Grant-SreAgentAdministratorOnAgent -AgentResourceId $agentId
}

Write-Host "`n=== Step 6: Upload platform custom agent ===" -ForegroundColor Cyan
if ($SkipCustomAgentUpload) {
    Write-Host 'Skipping custom agent upload (-SkipCustomAgentUpload set).'
} else {
    Publish-CustomAgentYaml `
        -AgentEndpoint $agentEndpoint `
        -YamlPath "$PSScriptRoot\..\platform\custom-agents\workload-liaison.yaml"
}

if ([string]::IsNullOrWhiteSpace($PlatformManagementGroupId)) {
    $rbacScope = "/subscriptions/$SubscriptionId"
    $scopeLabel = "subscription $SubscriptionId"
} else {
    $rbacScope = "/providers/Microsoft.Management/managementGroups/$PlatformManagementGroupId"
    $scopeLabel = "management group $PlatformManagementGroupId"
}

Write-Host "`n=== Step 7: Assign Reader on platform scope ===" -ForegroundColor Cyan
$readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
# Both identities need this: actionConfiguration/knowledgeGraphConfiguration execute
# under the UAMI, not the system-assigned principal (see modules/sre-agent.bicep).
foreach ($principalId in @($agentPrincipalId, $agentUamiPrincipalId)) {
    Grant-RoleAssignmentIfMissing `
        -AssigneeObjectId $principalId `
        -RoleDefinitionId $readerRoleId `
        -Scope $rbacScope `
        -Description "Platform SRE Agent reads platform landing zone resources" `
        -RoleLabel "Reader ($scopeLabel)"
}

Write-Host "`n=== Step 8: Assign Monitoring Reader on platform scope ===" -ForegroundColor Cyan
$monitoringReaderRoleId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'
foreach ($principalId in @($agentPrincipalId, $agentUamiPrincipalId)) {
    Grant-RoleAssignmentIfMissing `
        -AssigneeObjectId $principalId `
        -RoleDefinitionId $monitoringReaderRoleId `
        -Scope $rbacScope `
        -Description "Platform SRE Agent reads monitoring data in platform landing zone" `
        -RoleLabel "Monitoring Reader ($scopeLabel)"
}

# Persist outputs so deploy-escalation-proxy.ps1 / deploy-all.ps1 can read them automatically.
Set-DeployState -Key 'PlatformSubscriptionId' -Value $SubscriptionId
Set-DeployState -Key 'PlatformResourceGroup'  -Value $ResourceGroup
Set-DeployState -Key 'PlatformAgentName'      -Value $AgentName
Set-DeployState -Key 'PlatformAgentId'        -Value $agentId
Set-DeployState -Key 'PlatformAgentEndpoint'  -Value $agentEndpoint
Set-DeployState -Key 'PlatformAgentPrincipal' -Value $agentPrincipalId
Set-DeployState -Key 'PlatformAgentUamiPrincipal' -Value $agentUamiPrincipalId
Set-DeployState -Key 'PlatformAgentAppInsightsId' -Value $appInsightsId

Write-Host "`n=== Deployment complete ===" -ForegroundColor Green
Write-Host "Saved to deploy state ($(Get-DeployStatePath)). Values for the escalation proxy deployment:"
Write-Host "  PLATFORM_AGENT_ID:         $agentId"
Write-Host "  PLATFORM_AGENT_ENDPOINT:   $agentEndpoint"
Write-Host "  PLATFORM_AGENT_PRINCIPAL:  $agentPrincipalId"
Write-Host ""
Write-Host "Next step: Run scripts/deploy-escalation-proxy.ps1 (it reads these from deploy state automatically)."

return [ordered]@{
    PlatformAgentId        = $agentId
    PlatformAgentEndpoint  = $agentEndpoint
    PlatformAgentPrincipal = $agentPrincipalId
}
