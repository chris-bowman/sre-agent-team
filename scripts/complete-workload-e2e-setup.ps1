# scripts/complete-workload-e2e-setup.ps1
# Completes the reference Workload SRE Agent wiring after platform/proxy/workload
# infrastructure exists: operator RBAC, EscalationCaller grant, MCP connector
# refresh, custom-agent upload, and validation probes.

[CmdletBinding()]
param (
    [string] $SubscriptionId = '4686fb7a-2bf8-4366-b0ea-7b7c85e63bd7',
    [string] $ResourceGroup = 'workload-rg',
    [string] $AgentName = 'WorkloadApp',
    [string] $AgentEndpoint = '',
    [string] $ProxyEndpointUrl = 'https://sre-escalation-proxy.happyisland-89fe2a77.australiaeast.azurecontainerapps.io/mcp/',
    [string] $ProxyEntraClientId = '4c4797ca-bf0d-441f-aa2b-dc237e71d7c2',
    [string] $ProxyPrincipalId = '7de7f53c-39c1-41b4-883d-81063be6fcb6',
    [string] $ProxySubscriptionId = '',
    [string] $ProxyResourceGroup = 'platformsre-rg',
    [string] $ProxyAppName = 'sre-escalation-proxy',
    [string] $WorkloadPrincipalId = '',
    [string] $WorkloadUamiPrincipalId = '751d96ae-084f-4079-a734-38faed60d1ef'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

$ProxySubscriptionId = Resolve-Value -Provided $ProxySubscriptionId -StateKey 'ProxySubscriptionId'
if ([string]::IsNullOrWhiteSpace($ProxySubscriptionId)) { $ProxySubscriptionId = $SubscriptionId }

$agentResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/agents/$AgentName"
$connectorIdentity = "/subscriptions/$($SubscriptionId.ToLower())/resourcegroups/$($ResourceGroup.ToLower())/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$AgentName-id"

function Write-Step {
    param([string] $Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

Write-Step 'Set subscription and verify Graph token'
az account set --subscription $SubscriptionId
$signedInUserId = az ad signed-in-user show --query id -o tsv
if ([string]::IsNullOrWhiteSpace($signedInUserId)) {
    throw 'Unable to resolve signed-in user object ID from Microsoft Graph.'
}
Write-Host "Signed-in user object ID: $signedInUserId"

Write-Step 'Resolve current workload agent state'
$agent = az resource show --ids $agentResourceId -o json | ConvertFrom-Json
if ($agent.properties.provisioningState -ne 'Succeeded') {
    throw "Workload agent provisioningState is '$($agent.properties.provisioningState)', expected 'Succeeded'."
}
if ([string]::IsNullOrWhiteSpace($AgentEndpoint)) {
    $AgentEndpoint = $agent.properties.agentEndpoint
}
if ([string]::IsNullOrWhiteSpace($WorkloadPrincipalId)) {
    $WorkloadPrincipalId = $agent.identity.principalId
}
if ([string]::IsNullOrWhiteSpace($AgentEndpoint)) {
    throw 'Workload agent has no agentEndpoint yet.'
}
Write-Host "Agent endpoint: $AgentEndpoint"
Write-Host "System principal: $WorkloadPrincipalId"

Write-Step 'Grant operator SRE Agent Administrator on workload agent'
Grant-SreAgentAdministratorOnAgent -AgentResourceId $agentResourceId

Write-Step 'Update deployment state'
Set-DeployState -Key 'ProxyEndpointUrl' -Value $ProxyEndpointUrl
Set-DeployState -Key 'ProxyEntraClientId' -Value $ProxyEntraClientId
Set-DeployState -Key 'ProxyPrincipalId' -Value $ProxyPrincipalId
Set-DeployState -Key 'ProxySubscriptionId' -Value $ProxySubscriptionId
Set-DeployState -Key 'ProxyResourceGroup' -Value $ProxyResourceGroup
Set-DeployState -Key 'ProxyAppName' -Value $ProxyAppName
Set-DeployState -Key 'WorkloadAgentName' -Value $AgentName
Set-DeployState -Key 'WorkloadAgentId' -Value $agentResourceId
Set-DeployState -Key 'WorkloadAgentPrincipal' -Value $WorkloadPrincipalId
Set-DeployState -Key 'WorkloadAgentUamiPrincipal' -Value $WorkloadUamiPrincipalId
Set-DeployState -Key 'WorkloadAgentAppInsightsId' -Value ''

Write-Step 'Grant EscalationCaller app role to workload identities'
& "$PSScriptRoot\grant-workload-escalation.ps1" `
    -WorkloadPrincipalId $WorkloadUamiPrincipalId `
    -EntraAppId $ProxyEntraClientId `
    -WorkloadName $AgentName `
    -SubscriptionId $ProxySubscriptionId `
    -ResourceGroup $ProxyResourceGroup `
    -ProxyAppName $ProxyAppName

Write-Step 'Refresh MCP connector envelope'
Sync-McpConnectorEnvelope `
    -SubscriptionId $SubscriptionId `
    -ResourceGroup $ResourceGroup `
    -AgentName $AgentName `
    -ConnectorName 'platform-escalation-mi' `
    -EndpointUrl $ProxyEndpointUrl `
    -ArmScope "api://$ProxyEntraClientId/.default" `
    -ConnectorIdentity $connectorIdentity

Write-Step 'Connector ARM state'
az resource show --ids "$agentResourceId/connectors/platform-escalation-mi" `
    --query '{provisioningState:properties.provisioningState,dataSource:properties.dataSource,endpoint:properties.endpoint,identity:properties.identity,extendedProperties:properties.extendedProperties}' `
    -o json

Write-Step 'Wait for connector status'
$connectorConnected = Wait-McpConnectorConnected `
    -AgentEndpoint $AgentEndpoint `
    -ConnectorName 'platform-escalation-mi' `
    -MaxAttempts 60 `
    -DelaySeconds 15
Write-Host "ConnectorConnected=$connectorConnected"

Write-Step 'Publish custom agents'
Publish-CustomAgentYaml `
    -AgentEndpoint $AgentEndpoint `
    -YamlPath "$PSScriptRoot\..\workload\custom-agents\platform-escalation.yaml"
Publish-CustomAgentYaml `
    -AgentEndpoint $AgentEndpoint `
    -YamlPath "$PSScriptRoot\..\workload\custom-agents\workload-escalation-parent.yaml"

Write-Step 'Verify data-plane custom agents'
$accessToken = az account get-access-token --resource https://azuresre.dev --query accessToken -o tsv
$headers = @{ Authorization = "Bearer $accessToken" }
$agents = Invoke-RestMethod `
    -Method Get `
    -Uri "$($AgentEndpoint.TrimEnd('/'))/api/v2/extendedAgent/agents" `
    -Headers $headers `
    -TimeoutSec 30
$agents | ConvertTo-Json -Depth 20

Write-Step 'Verify data-plane connector status'
try {
    $connectorStatus = Invoke-RestMethod `
        -Method Get `
        -Uri "$($AgentEndpoint.TrimEnd('/'))/api/v2/extendedAgent/connectors/platform-escalation-mi/status" `
        -Headers $headers `
        -TimeoutSec 30
    $connectorStatus | ConvertTo-Json -Depth 20
} catch {
    Write-Warning "Connector status check failed: $($_.Exception.Message)"
}

Write-Step 'Verify final Azure resources'
az resource show --ids $agentResourceId `
    --query '{name:name,location:location,provisioningState:properties.provisioningState,agentEndpoint:properties.agentEndpoint,systemPrincipal:identity.principalId}' `
    -o json
az identity show -g $ResourceGroup -n "$AgentName-id" `
    --query '{name:name,location:location,principalId:principalId,clientId:clientId}' `
    -o json

Write-Step 'Verify app-role assignments'
$proxySpObjectId = az ad sp show --id $ProxyEntraClientId --query id -o tsv
az rest `
    --method GET `
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$proxySpObjectId/appRoleAssignedTo" `
    --query "value[?principalId=='$WorkloadUamiPrincipalId' || principalId=='$WorkloadPrincipalId'].{principalDisplayName:principalDisplayName,principalId:principalId,appRoleId:appRoleId}" `
    -o json

if (-not $connectorConnected) {
    Write-Warning 'Connector remains Connecting. If proxy logs still show roles: [], restart the WorkloadApp agent runtime/hosting layer and rerun this script.'
}
