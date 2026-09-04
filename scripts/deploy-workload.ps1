# scripts/deploy-workload.ps1
# Deploy a Workload SRE Agent for an application team.
# App teams run this after filling in workload/main.bicepparam.
# The platform team must then run grant-workload-escalation.ps1.
#
# Prerequisites:
#   - az CLI with Contributor + User Access Administrator on the workload deployment scope
#   - Values from deploy-escalation-proxy.ps1 output (proxy endpoint + Entra client ID)

[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $AgentName,
    [Parameter(Mandatory)] [string] $WorkloadDisplayName,
    [Parameter(Mandatory)] [string] $ScopedResourceGroups,
    # Optional: resolved from deploy state (deploy-escalation-proxy.ps1) when omitted.
    [string] $EscalationProxyEndpointUrl = '',
    [string] $EscalationProxyEntraClientId = '',
    [string] $ParameterFile = "$PSScriptRoot\..\workload\main.bicepparam",
    [string] $Location = 'australiaeast',
    [switch] $EnableApplicationInsights,
    [switch] $SkipCustomAgentUpload,
    [switch] $SkipCurrentCallerAgentAdminAssignment,
    [switch] $SkipConnectorMaterialization
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Shared helpers: state file, robust custom-agent upload, RBAC + endpoint resolution.
. "$PSScriptRoot\common.ps1"

# Allow proxy values to come from deploy state when not passed explicitly
# (e.g. when chained after deploy-escalation-proxy.ps1 or via deploy-all.ps1).
$EscalationProxyEndpointUrl   = Resolve-Value -Provided $EscalationProxyEndpointUrl   -StateKey 'ProxyEndpointUrl'
$EscalationProxyEntraClientId = Resolve-Value -Provided $EscalationProxyEntraClientId -StateKey 'ProxyEntraClientId'

if ([string]::IsNullOrWhiteSpace($EscalationProxyEndpointUrl) -or [string]::IsNullOrWhiteSpace($EscalationProxyEntraClientId)) {
    throw 'EscalationProxyEndpointUrl and EscalationProxyEntraClientId are required. Pass them explicitly or run deploy-escalation-proxy.ps1 first so they are stored in deploy state.'
}

Write-Host "=== Step 1: Set active subscription ===" -ForegroundColor Cyan
az account set --subscription $SubscriptionId
Write-Host "Subscription: $SubscriptionId"

Write-Host "`n=== Step 2: Ensure resource group exists ===" -ForegroundColor Cyan
az group create --name $ResourceGroup --location $Location --output table

Write-Host "`n=== Step 3: Register SRE Agent resource provider (idempotent) ===" -ForegroundColor Cyan
az provider register --namespace 'Microsoft.App' --wait

Write-Host "`n=== Step 4: Deploy workload SRE Agent ===" -ForegroundColor Cyan
$deployOutput = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file "$PSScriptRoot\..\workload\main.bicep" `
    --parameters $ParameterFile `
    --parameters `
        agentName=$AgentName `
        workloadDisplayName="$WorkloadDisplayName" `
        location=$Location `
        scopedResourceGroups="$ScopedResourceGroups" `
        enableApplicationInsights=$($EnableApplicationInsights.IsPresent) `
        escalationProxyEndpointUrl=$EscalationProxyEndpointUrl `
        escalationProxyEntraClientId=$EscalationProxyEntraClientId `
    --query 'properties.outputs' `
    --output json | ConvertFrom-Json

$agentId       = $deployOutput.agentId.value
$principalId   = $deployOutput.principalId.value
$uamiPrincipal = $deployOutput.uamiPrincipalId.value
$appInsightsId = if ($deployOutput.PSObject.Properties.Name -contains 'applicationInsightsId') { $deployOutput.applicationInsightsId.value } else { '' }

$agentEndpoint = Resolve-AgentEndpoint `
    -SubscriptionId $SubscriptionId `
    -ResourceGroup $ResourceGroup `
    -AgentName $AgentName

Write-Host "Workload agent deployed."
Write-Host "  Agent ID:      $agentId"
Write-Host "  Endpoint:      $agentEndpoint"
Write-Host "  Principal ID:  $principalId"
Write-Host "  UAMI Principal: $uamiPrincipal"
if (-not [string]::IsNullOrWhiteSpace($appInsightsId)) {
    Write-Host "  App Insights:  $appInsightsId"
}

Write-Host "`n=== Step 4a: Materialize MCP connector configuration ===" -ForegroundColor Cyan
if ($SkipConnectorMaterialization) {
    Write-Host 'Skipping connector materialization (-SkipConnectorMaterialization set).'
} else {
    # Bicep sets extendedProperties on the connector, but the data plane can
    # persist it as null on first create and leave the connector stuck in
    # 'Connecting'. This follow-up PUT + poll reliably fixes it.
    # NOTE: assumes the default AzureARM connector auth type — pass
    # -SkipConnectorMaterialization if your bicepparam overrides it to ManagedIdentity.
    $connectorName = 'platform-escalation-mi'
    Sync-McpConnectorEnvelope `
        -SubscriptionId $SubscriptionId `
        -ResourceGroup $ResourceGroup `
        -AgentName $AgentName `
        -ConnectorName $connectorName `
        -EndpointUrl $EscalationProxyEndpointUrl `
        -ArmScope "api://$EscalationProxyEntraClientId/.default"

    Wait-McpConnectorConnected `
        -AgentEndpoint $agentEndpoint `
        -ConnectorName $connectorName | Out-Null
}

Write-Host "`n=== Step 5: Ensure current caller can use/manage this SRE Agent ===" -ForegroundColor Cyan
if ($SkipCurrentCallerAgentAdminAssignment) {
    Write-Host 'Skipping current-caller SRE Agent Administrator assignment (-SkipCurrentCallerAgentAdminAssignment set).'
} else {
    Grant-SreAgentAdministratorOnAgent -AgentResourceId $agentId
}

Write-Host "`n=== Step 6: Upload custom agents ===" -ForegroundColor Cyan
if ($SkipCustomAgentUpload) {
    Write-Host 'Skipping custom agent upload (-SkipCustomAgentUpload set).'
} else {
    Publish-CustomAgentYaml `
        -AgentEndpoint $agentEndpoint `
        -YamlPath "$PSScriptRoot\..\workload\custom-agents\platform-escalation.yaml"

    Publish-CustomAgentYaml `
        -AgentEndpoint $agentEndpoint `
        -YamlPath "$PSScriptRoot\..\workload\custom-agents\workload-escalation-parent.yaml"
}

Write-Host "`n=== Deployment complete ===" -ForegroundColor Green

# Persist the workload principal so grant-workload-escalation.ps1 / deploy-all.ps1 can read it.
Set-DeployState -Key 'WorkloadAgentName'    -Value $AgentName
Set-DeployState -Key 'WorkloadAgentId'      -Value $agentId
Set-DeployState -Key 'WorkloadAgentEndpoint' -Value $agentEndpoint
Set-DeployState -Key 'WorkloadAgentPrincipal' -Value $principalId
Set-DeployState -Key 'WorkloadAgentUamiPrincipal' -Value $uamiPrincipal
Set-DeployState -Key 'WorkloadAgentAppInsightsId' -Value $appInsightsId

Write-Host "IMPORTANT: Provide the following to the platform team to enable escalation access:"
Write-Host "  WORKLOAD_AGENT_PRINCIPAL_ID: $uamiPrincipal"
Write-Host ""
Write-Host "Platform team must then run:"
Write-Host "  scripts/grant-workload-escalation.ps1 -WorkloadPrincipalId $uamiPrincipal -EntraAppId $EscalationProxyEntraClientId -WorkloadName $AgentName"

return [ordered]@{
    WorkloadAgentId        = $agentId
    WorkloadAgentPrincipal = $principalId
    WorkloadAgentUamiPrincipal = $uamiPrincipal
}
