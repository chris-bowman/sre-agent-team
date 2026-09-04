// workload/main.bicep
// Deploys a Workload SRE Agent for a single application team.
// Scope: resource group in the application landing zone subscription.
//
// App teams fill in main.bicepparam and run deploy-workload.ps1.
// The platform team must have already deployed the escalation proxy and
// run grant-workload-escalation.ps1 for this agent's managed identity.

targetScope = 'resourceGroup'

@description('Name for this workload SRE Agent. Use a name that identifies your app team.')
param agentName string

@description('Azure region.')
param location string = resourceGroup().location

@description('Display name shown in the portal and in escalation messages.')
param workloadDisplayName string = agentName

@description('Comma-separated list of resource group names this agent is responsible for.')
param scopedResourceGroups string

@description('HTTPS URL of the Platform Escalation Proxy MCP endpoint.')
param escalationProxyEndpointUrl string

@allowed([
  'AzureARM'
  'ManagedIdentity'
])
@description('Authentication mode for the platform escalation connector. AzureARM currently matches the connected portal/runtime shape in this tenant. ManagedIdentity is kept for compatibility testing only.')
param escalationConnectorAuthType string = 'AzureARM'

@description('Entra app client ID of the escalation proxy. Used to populate the connector token audience/scope.')
param escalationProxyEntraClientId string

@description('Enable Application Insights logging for the workload SRE agent.')
param enableApplicationInsights bool = false

// ── Workload SRE Agent ───────────────────────────────────────────────────────
module workloadAgent '../modules/sre-agent.bicep' = {
  name: 'deploy-workload-agent'
  params: {
    name: agentName
    location: location
    enableApplicationInsights: enableApplicationInsights
    tags: {
      workloadDisplayName: workloadDisplayName
      scopedResourceGroups: scopedResourceGroups
    }
    // Matches the Reader/Monitoring Reader RBAC scope assigned below.
    managedResources: [for resourceGroupName in scopedResourceGroupNames: '/subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroupName}']
  }
}

// ── RBAC: Reader on every declared workload resource group ──────────────────
// The workload scope is explicit and subscription-local. The agent's MI has
// no permissions outside these resource groups.
var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
var monitoringReaderRoleId = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'
var scopedResourceGroupNames = [for resourceGroupName in split(scopedResourceGroups, ','): trim(resourceGroupName)]

// Action/knowledge-graph execution runs under the UAMI (see modules/sre-agent.bicep),
// not the system-assigned identity, so both must be granted or the agent can't
// actually read the resources it's scoped to. Bicep for-loops can't iterate an
// array built from module outputs, so this is two loops over resource groups
// (a compile-time-known list) rather than one loop over {rg, principal} pairs.
module readerAssignments '../modules/rbac-assignments.bicep' = [for resourceGroupName in scopedResourceGroupNames: {
  name: 'rbac-reader-${uniqueString(resourceGroupName)}'
  scope: resourceGroup(subscription().subscriptionId, resourceGroupName)
  params: {
    principalId: workloadAgent.outputs.principalId
    roleDefinitionId: readerRoleId
    roleDescription: '${agentName} agent (system-assigned) reads declared workload resource group ${resourceGroupName}'
  }
}]

module readerAssignmentsUami '../modules/rbac-assignments.bicep' = [for resourceGroupName in scopedResourceGroupNames: {
  name: 'rbac-reader-uami-${uniqueString(resourceGroupName)}'
  scope: resourceGroup(subscription().subscriptionId, resourceGroupName)
  params: {
    principalId: workloadAgent.outputs.uamiPrincipalId
    roleDefinitionId: readerRoleId
    roleDescription: '${agentName} agent (user-assigned) reads declared workload resource group ${resourceGroupName}'
  }
}]

module monitoringReaderAssignments '../modules/rbac-assignments.bicep' = [for resourceGroupName in scopedResourceGroupNames: {
  name: 'rbac-monitoring-reader-${uniqueString(resourceGroupName)}'
  scope: resourceGroup(subscription().subscriptionId, resourceGroupName)
  params: {
    principalId: workloadAgent.outputs.principalId
    roleDefinitionId: monitoringReaderRoleId
    roleDescription: '${agentName} agent (system-assigned) reads monitoring data in declared workload resource group ${resourceGroupName}'
  }
}]

module monitoringReaderAssignmentsUami '../modules/rbac-assignments.bicep' = [for resourceGroupName in scopedResourceGroupNames: {
  name: 'rbac-monitoring-reader-uami-${uniqueString(resourceGroupName)}'
  scope: resourceGroup(subscription().subscriptionId, resourceGroupName)
  params: {
    principalId: workloadAgent.outputs.uamiPrincipalId
    roleDefinitionId: monitoringReaderRoleId
    roleDescription: '${agentName} agent (user-assigned) reads monitoring data in declared workload resource group ${resourceGroupName}'
  }
}]

// The portal appears to resolve selected UAMI by exact string comparison against
// agent.identity.userAssignedIdentities keys. Use the same canonical path form.
var connectorUamiResourceId = '${toLower(subscription().id)}/resourcegroups/${toLower(resourceGroup().name)}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${agentName}-id'

// ── MCP Connector: Platform Escalation Proxy ─────────────────────────────────
// The workload agent connects to the platform escalation proxy as a Streamable-HTTP MCP server.
// The agent will obtain an Entra token (using its own MI) for the proxy audience.
// NOTE: No secret is stored here — the agent handles token acquisition using its MI.
module escalationProxyConnector '../modules/mcp-connector-streamable-http.bicep' = {
  name: 'mcp-connector-platform-escalation'
  params: {
    agentName: workloadAgent.outputs.agentName
    connectorName: 'platform-escalation-mi'
    endpointUrl: escalationProxyEndpointUrl
    connectorAuthType: escalationConnectorAuthType
    // Force the connector to use the workload agent's user-assigned identity.
    connectorIdentity: connectorUamiResourceId
    // In AzureARM mode, the connected portal/runtime shape stores the audience under armScope.
    armScope: escalationConnectorAuthType == 'AzureARM'
      ? 'api://${escalationProxyEntraClientId}/.default'
      : ''
    // In ManagedIdentity mode, the connector acquires a token for the proxy app.
    managedIdentityScope: escalationConnectorAuthType == 'ManagedIdentity'
      ? 'api://${escalationProxyEntraClientId}/.default'
      : ''
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
@description('Resource ID of the workload SRE Agent.')
output agentId string = workloadAgent.outputs.agentId

@description('Principal ID of the workload agent MI — provide to the platform team for escalation access.')
output principalId string = workloadAgent.outputs.principalId

@description('Principal ID of the workload agent user-assigned MI (WorkloadApp-id). Use this for MCP connector app-role assignment when connector identity is user-assigned.')
output uamiPrincipalId string = workloadAgent.outputs.uamiPrincipalId

@description('Run this on the platform team side to grant escalation access.')
output grantEscalationCommand string = 'Run scripts/grant-workload-escalation.ps1 -WorkloadPrincipalId ${workloadAgent.outputs.uamiPrincipalId}'

@description('Application Insights resource ID when agent logging is enabled.')
output applicationInsightsId string = workloadAgent.outputs.applicationInsightsId
