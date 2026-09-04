// modules/sre-agent.bicep
// Reusable module to deploy an Azure SRE Agent (Microsoft.App/agents).
// Deploy at resource group scope.
// Note: displayName, instructions, and other agent configuration are applied
// via the data-plane API post-deploy and are not ARM resource properties.

@description('Name of the SRE Agent resource.')
param name string

@description('Azure region for the agent.')
param location string = resourceGroup().location

@description('Optional tags to apply to the SRE Agent resource.')
param tags object = {}

@description('Enable Application Insights logging for this agent.')
param enableApplicationInsights bool = false

@description('Log Analytics workspace name used when Application Insights logging is enabled.')
param logAnalyticsWorkspaceName string = '${name}-logs'

@description('Application Insights component name used when agent logging is enabled.')
param applicationInsightsName string = '${name}-appi'

@description('Azure resource IDs (subscription/resource group/resource) this agent manages. Leaving this empty means the agent has no resources in scope, which shows as no access in the portal.')
param managedResources array = []

// User-assigned managed identity required for knowledgeGraphConfiguration and actionConfiguration.
resource agentIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: '${name}-id'
  location: location
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (enableApplicationInsights) {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
      searchVersion: 1
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = if (enableApplicationInsights) {
  name: applicationInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

var baseAgentProperties = {
  upgradeChannel: 'Stable'
  defaultModel: {
    name: 'Automatic'
    provider: 'Anthropic'
  }
  knowledgeGraphConfiguration: {
    identity: agentIdentity.id
    managedResources: managedResources
  }
  actionConfiguration: {
    accessLevel: 'Low'
    identity: agentIdentity.id
    mode: 'Review'
  }
  #disable-next-line BCP037
  experimentalSettings: {
    EnableWorkspaceTools: true
  }
}

var appInsightsLoggingProperties = enableApplicationInsights
  ? {
      logConfiguration: {
        applicationInsightsConfiguration: {
          appId: appInsights!.properties.AppId
          connectionString: appInsights!.properties.ConnectionString
        }
      }
    }
  : {}

var agentProperties = union(baseAgentProperties, appInsightsLoggingProperties)

resource agent 'Microsoft.App/agents@2026-01-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned, UserAssigned'
    userAssignedIdentities: {
      '${agentIdentity.id}': {}
    }
  }
  properties: agentProperties
}

@description('Resource ID of the SRE Agent.')
output agentId string = agent.id

@description('Data-plane endpoint of the SRE Agent, as reported by ARM. Empty if the agent is still provisioning — use the post-deploy ARM lookup in the calling script as a fallback.')
output agentEndpoint string = any(agent).properties.agentEndpoint ?? ''

@description('Principal ID of the system-assigned managed identity.')
output principalId string = agent.identity.principalId

@description('Principal ID of the user-assigned managed identity.')
output uamiPrincipalId string = agentIdentity.properties.principalId

@description('Resource ID of the user-assigned managed identity.')
output uamiResourceId string = agentIdentity.id

@description('Agent resource name.')
output agentName string = agent.name

@description('Application Insights resource ID when enabled, else empty.')
output applicationInsightsId string = enableApplicationInsights ? appInsights.id : ''

@description('Application Insights name when enabled, else empty.')
output applicationInsightsName string = enableApplicationInsights ? appInsights.name : ''
