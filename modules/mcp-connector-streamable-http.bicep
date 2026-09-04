// modules/mcp-connector-streamable-http.bicep
// Reusable module to add a Streamable-HTTP MCP connector to an existing SRE Agent.
// Deploy at resource group scope, in the same RG as the agent.

@description('Name of the SRE Agent to attach the connector to.')
param agentName string

@description('Unique name for this MCP connector (alphanumeric, hyphens, max 64 chars).')
param connectorName string

@description('Full HTTPS URL of the remote MCP server endpoint.')
param endpointUrl string

@description('Optional secure data source value for the connector. Defaults to the endpoint URL.')
@secure()
param dataSource string = ''

@description('Bearer token for authenticating to the remote MCP server. Leave empty to use the agent managed identity instead.')
@secure()
param bearerToken string = ''

@allowed([
  'ManagedIdentity'
  'AzureARM'
  'BearerToken'
])
@description('Authentication mode for the connector. Use AzureARM to match current portal-connected behavior, ManagedIdentity for endpoint+scope MI, or BearerToken for static token auth.')
param connectorAuthType string = 'ManagedIdentity'

@description('Token scope used when authenticating with managed identity, for example api://<app-client-id>/.default. Only used when bearerToken is empty.')
param managedIdentityScope string = ''

@description('Optional ARM scope used when connectorAuthType is AzureARM. Leave empty to let the service manage scope implicitly.')
param armScope string = ''

@description('Identity selector for connector authentication. Use system for system-assigned MI, or pass a user-assigned identity resource ID.')
param connectorIdentity string = 'system'

resource agent 'Microsoft.App/agents@2026-01-01' existing = {
  name: agentName
}

var managedIdentityExtendedProps = {
  type: 'http'
  endpoint: endpointUrl
  authType: 'ManagedIdentity'
  scope: managedIdentityScope
}

var azureArmExtendedProps = empty(armScope)
  ? {
      type: 'http'
      endpoint: endpointUrl
      authType: 'AzureARM'
    }
  : {
      type: 'http'
      endpoint: endpointUrl
      authType: 'AzureARM'
      armScope: armScope
    }

var bearerTokenExtendedProps = {
  type: 'http'
  endpoint: endpointUrl
  authType: 'BearerToken'
  bearerToken: bearerToken
}

var authExtendedProps = connectorAuthType == 'BearerToken'
  ? bearerTokenExtendedProps
  : (connectorAuthType == 'AzureARM' ? azureArmExtendedProps : managedIdentityExtendedProps)

var resolvedDataSource = !empty(dataSource) ? dataSource : endpointUrl

resource mcpConnector 'Microsoft.App/agents/connectors@2026-01-01' = {
  parent: agent
  name: connectorName
  properties: {
    dataConnectorType: 'Mcp'
    dataSource: resolvedDataSource
    endpoint: endpointUrl
    extendedProperties: authExtendedProps
    identity: connectorIdentity
  }
}

output connectorId string = mcpConnector.id
output connectorName string = mcpConnector.name
