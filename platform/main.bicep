// platform/main.bicep
// Deploys the Platform SRE Agent into the platform team's Azure scope.
// Scope: resource group (deploy with: az deployment group create)
//
// This agent is owned by the central cloud platform team.
// In production, its managed identity is typically scoped to the Platform landing zone
// management group. For smaller or test environments, subscription-scoped access is also supported.

targetScope = 'resourceGroup'

@description('Name for the platform SRE Agent resource.')
param agentName string = 'sre-platform'

@description('Azure region.')
param location string = resourceGroup().location

@description('Optional ALZ Platform management group ID (e.g. "mg-platform"). When supplied, the agent MI receives Reader + Monitoring Reader there. If omitted, assign those roles at the subscription scope instead.')
param platformManagementGroupId string = ''

@description('Enable Application Insights logging for the platform SRE agent.')
param enableApplicationInsights bool = false

// ----- Platform SRE Agent -----
module platformAgent '../modules/sre-agent.bicep' = {
  name: 'deploy-platform-agent'
  params: {
    name: agentName
    location: location
    enableApplicationInsights: enableApplicationInsights
    // Matches the Reader/Monitoring Reader RBAC scope assigned below (or at
    // the management group, when platformManagementGroupId is used).
    managedResources: [subscription().id]
  }
}

// ----- RBAC: Reader on platform scope -----
// Grants the platform agent MI read access to the platform estate.
// scripts/deploy-platform.ps1 assigns Reader + Monitoring Reader at either management-group
// scope (recommended) or subscription scope (test/lab environments).

// Built-in role IDs (do not change)
var readerRoleId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

// Action/knowledge-graph execution runs under the UAMI (see modules/sre-agent.bicep),
// not the system-assigned identity, so both must be granted for the agent to
// actually be able to read its own resource group.
module readerRgAssignmentSystem '../modules/rbac-assignments.bicep' = {
  name: 'rbac-reader-rg-system'
  params: {
    principalId: platformAgent.outputs.principalId
    roleDefinitionId: readerRoleId
    roleDescription: 'Platform agent (system-assigned) reads its own resource group'
  }
}

module readerRgAssignmentUami '../modules/rbac-assignments.bicep' = {
  name: 'rbac-reader-rg-uami'
  params: {
    principalId: platformAgent.outputs.uamiPrincipalId
    roleDefinitionId: readerRoleId
    roleDescription: 'Platform agent (user-assigned) reads its own resource group'
  }
}

// ----- Outputs -----
@description('Resource ID of the platform SRE Agent.')
output agentId string = platformAgent.outputs.agentId

@description('Data-plane endpoint (pass to grant-workload-access and escalation proxy).')
output agentEndpoint string = platformAgent.outputs.agentEndpoint

@description('Principal ID of the platform agent MI.')
output principalId string = platformAgent.outputs.principalId

@description('Principal ID of the platform agent user-assigned MI. Action/knowledge-graph execution runs under this identity, so it must be granted Reader/Monitoring Reader too — not just the system-assigned principal.')
output uamiPrincipalId string = platformAgent.outputs.uamiPrincipalId

@description('Application Insights resource ID when agent logging is enabled.')
output applicationInsightsId string = platformAgent.outputs.applicationInsightsId

@description('RBAC guidance to run after deployment (see deploy-platform.ps1).')
output postDeployNote string = empty(platformManagementGroupId)
  ? 'Assign Reader and Monitoring Reader to the platform agent principal at the platform subscription scope.'
  : 'Assign Reader and Monitoring Reader to the platform agent principal at management group ${platformManagementGroupId}.'
