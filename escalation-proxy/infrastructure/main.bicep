// escalation-proxy/infrastructure/main.bicep
// Deploys the Platform Escalation MCP Proxy as an Azure Container App.
// Owned and operated by the platform team.
//
// This template:
//   1. Creates a Container App Environment + Container App running the proxy image.
//   2. Assigns the Container App's managed identity "SRE Agent Administrator" on the platform agent.
//   3. Outputs the proxy endpoint URL and an Entra app role assignment command.
//
// NOTE: The Entra app registration (with EscalationCaller app role) must be created
// manually in Entra ID (az ad app create) before deploying — see deploy-escalation-proxy.ps1.

targetScope = 'resourceGroup'

@description('Name of the Container App (proxy).')
param proxyAppName string = 'sre-escalation-proxy'

@description('Azure region.')
param location string = resourceGroup().location

@description('Immutable container image to deploy. Format: <registry>/<image>@sha256:<digest>')
param containerImage string

@description('Resource ID of the platform SRE Agent (Microsoft.App/agents).')
param platformAgentResourceId string

@description('Data-plane endpoint of the platform SRE Agent (https://*.azuresre.ai).')
param platformAgentEndpoint string

@description('Entra tenant ID.')
param tenantId string = tenant().tenantId

@description('Entra app registration client ID for the proxy (created before deployment).')
param entraAppClientId string

@secure()
@description('Operator-managed same-tenant caller policies serialized as JSON.')
param callerPoliciesJson string = ''

@description('Azure App Configuration store name for dynamic caller policy. The deployment script creates and seeds it before the Container App starts.')
param appConfigurationName string = take('${proxyAppName}-config', 50)

@description('App Configuration key containing the caller policy JSON array.')
param callerPolicyKey string = 'escalation/caller-policies'

@description('App Configuration label for the active caller policy environment.')
param callerPolicyLabel string = 'production'

@minValue(1)
@description('Seconds between caller policy refresh attempts.')
param callerPolicyRefreshSeconds int = 30

@minValue(1)
@description('Maximum age of the last-known-good caller policy before authorization fails closed.')
param callerPolicyMaxStalenessSeconds int = 300

@description('Role definition GUID for the built-in "SRE Agent Administrator" role. Resolve at deploy time with: az role definition list --name "SRE Agent Administrator" --query "[0].name" -o tsv. deploy-escalation-proxy.ps1 passes this automatically.')
param sreAgentAdminRoleDefinitionId string

@description('Login server of the Azure Container Registry (e.g. myregistry.azurecr.io). Used by the Container App to authenticate image pulls via managed identity.')
param acrLoginServer string

@description('Optional revision suffix to force a new Container App revision when redeploying the same image tag.')
param revisionSuffix string = ''

@description('Storage account name for the shared investigation registry. Must be globally unique and 3-24 lowercase alphanumeric characters.')
param registryStorageAccountName string = take('sre${uniqueString(resourceGroup().id)}registry', 24)

@description('Role definition GUID for Storage Table Data Contributor. The deployment script resolves this automatically.')
param storageTableDataContributorRoleDefinitionId string = ''

@allowed(['table', 'memory'])
@description('Investigation registry backend. Use "memory" if tenant policy forces the storage account publicNetworkAccess off and no private endpoint is configured yet (see docs/threat-model.md).')
param registryBackend string = 'table'

@allowed(['true', 'false'])
@description('Enable VNet integration and private Table endpoint networking for production Table mode.')
param enablePrivateNetworking string = 'false'

@description('Name of the VNet created for the private production profile.')
param privateNetworkName string = '${proxyAppName}-vnet'

@description('Address space for the private production VNet.')
param privateNetworkAddressPrefix string = '10.42.0.0/16'

@description('Infrastructure subnet prefix for the Container Apps environment. Use at least /27.')
param containerEnvironmentSubnetPrefix string = '10.42.0.0/27'

@description('Private endpoint subnet prefix for the registry Storage account.')
param storagePrivateEndpointSubnetPrefix string = '10.42.1.0/28'

@description('Comma-separated MCP Host header allowlist. The deployment script replaces the initial local-safe value with the emitted Container App FQDN.')
param mcpAllowedHosts string = '127.0.0.1:*,localhost:*,testserver,testserver:*'

@allowed(['true', 'false'])
@description('Enable MCP SDK DNS rebinding protection. Keep true for normal deployments; false is diagnostic-only for connector host compatibility testing.')
param mcpEnableDnsRebindingProtection string = 'true'

@minValue(1)
@description('Minimum Container App replicas.')
param minReplicas int = 1

@minValue(1)
@description('Maximum Container App replicas for the table-backed registry. Memory mode is always capped at one replica.')
param maxReplicas int = 5

@minValue(30)
@maxValue(730)
@description('Log Analytics workspace retention in days.')
param logRetentionDays int = 30

@minValue(1)
@maxValue(365)
@description('Retention in days for active investigation metadata.')
param activeMetadataRetentionDays int = 1

@minValue(1)
@maxValue(365)
@description('Retention in days for terminal investigation and finalized findings metadata. Findings content is not persisted.')
param finalFindingsMetadataRetentionDays int = 7

@minValue(1)
@maxValue(86400)
@description('Seconds between bounded investigation registry expiry cleanup sweeps in each proxy replica.')
param expiryCleanupIntervalSeconds int = 300

@minValue(1)
@description('Number of exhausted Platform SRE Agent requests that opens the circuit breaker.')
param platformCircuitFailureThreshold int = 5

@minValue(1)
@description('Seconds an open Platform SRE Agent circuit waits before allowing one recovery probe.')
param platformCircuitRecoverySeconds int = 30

// ── Log Analytics for Container Apps ────────────────────────────────────────
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${proxyAppName}-logs'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: logRetentionDays
  }
}

resource registryStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = if (registryBackend == 'table') {
  name: registryStorageAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    publicNetworkAccess: enablePrivateNetworking == 'true' ? 'Disabled' : 'Enabled'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

resource registryTableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = if (registryBackend == 'table') {
  name: 'default'
  parent: registryStorage
}

resource registryTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = if (registryBackend == 'table') {
  name: 'InvestigationRegistry'
  parent: registryTableService
}

// ── Private networking profile ──────────────────────────────────────────────
// The profile is opt-in so memory-backed local/staging deployments retain their
// existing footprint. Table production deployments should enable it under the
// tenant policy that disables public Storage access.
resource privateNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: privateNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [privateNetworkAddressPrefix]
    }
    subnets: [
      {
        name: 'containerapps-infrastructure'
        properties: {
          addressPrefix: containerEnvironmentSubnetPrefix
          natGateway: {
            id: containerNatGateway.id
          }
          delegations: [
            {
              name: 'container-apps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'storage-private-endpoints'
        properties: {
          addressPrefix: storagePrivateEndpointSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

resource containerOutboundIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: '${proxyAppName}-egress-ip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource containerNatGateway 'Microsoft.Network/natGateways@2023-11-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: '${proxyAppName}-nat'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIpAddresses: [
      {
        id: containerOutboundIp.id
      }
    ]
    idleTimeoutInMinutes: 10
  }
}

resource privateDnsZone 'Microsoft.Network/privateDnsZones@2020-06-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: 'privatelink.table.${environment().suffixes.storage}'
  location: 'global'
}

resource privateDnsVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: '${privateNetworkName}-link'
  parent: privateDnsZone
  location: 'global'
  properties: {
    virtualNetwork: {
      id: privateNetwork.id
    }
    registrationEnabled: false
  }
}

resource registryPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: '${registryStorageAccountName}-table-pe'
  location: location
  properties: {
    subnet: {
      id: resourceId('Microsoft.Network/virtualNetworks/subnets', privateNetwork.name, 'storage-private-endpoints')
    }
    privateLinkServiceConnections: [
      {
        name: 'table'
        properties: {
          privateLinkServiceId: registryStorage.id
          groupIds: ['table']
        }
      }
    ]
  }
}

resource registryPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = if (enablePrivateNetworking == 'true' && registryBackend == 'table') {
  name: 'table-dns'
  parent: registryPrivateEndpoint
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'table'
        properties: {
          privateDnsZoneId: privateDnsZone.id
        }
      }
    ]
  }
}

// ── User-Assigned Managed Identity for the proxy ─────────────────────────────
// A UAMI is used instead of SystemAssigned so its principalId and clientId are
// available before the Container App resource is declared.
resource proxyUami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${proxyAppName}-id'
  location: location
}

resource appConfiguration 'Microsoft.AppConfiguration/configurationStores@2024-05-01' = {
  name: appConfigurationName
  location: location
  sku: {
    name: 'free'
  }
  properties: {
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
    dataPlaneProxy: {
      authenticationMode: 'Pass-through'
      privateLinkDelegation: 'Disabled'
    }
  }
}

resource appConfigurationReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appConfiguration.id, proxyUami.id, 'App Configuration Data Reader')
  scope: appConfiguration
  properties: {
    principalId: proxyUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '516239f1-63e1-4d78-a4de-a74fb236a071')
    principalType: 'ServicePrincipal'
    description: 'Escalation proxy reads dynamic caller authorization policy'
  }
}

// ── Container App Environment ─────────────────────────────────────────────────
resource containerEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${proxyAppName}-env'
  location: location
  properties: {
    vnetConfiguration: enablePrivateNetworking == 'true' && registryBackend == 'table' ? {
      infrastructureSubnetId: resourceId('Microsoft.Network/virtualNetworks/subnets', privateNetwork.name, 'containerapps-infrastructure')
    } : null
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// ── Container App (the proxy) ────────────────────────────────────────────────
resource proxyApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: proxyAppName
  location: location
  dependsOn: [appConfigurationReaderAssignment]

  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${proxyUami.id}': {} }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          identity: proxyUami.id
        }
      ]
    }
    template: {
      revisionSuffix: revisionSuffix
      containers: [
        {
          name: 'proxy'
          image: containerImage
          resources: { cpu: json('0.5'), memory: '1Gi' }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health/live'
                port: 8080
              }
              initialDelaySeconds: 10
              periodSeconds: 30
              timeoutSeconds: 5
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health/ready'
                port: 8080
              }
              initialDelaySeconds: 15
              periodSeconds: 30
              timeoutSeconds: 5
            }
          ]
          env: [
            { name: 'PLATFORM_AGENT_ENDPOINT', value: platformAgentEndpoint }
            { name: 'ENTRA_TENANT_ID', value: tenantId }
            { name: 'ENTRA_CLIENT_ID', value: entraAppClientId }
            { name: 'AZURE_CLIENT_ID', value: proxyUami.properties.clientId }
            { name: 'CALLER_POLICIES_JSON', value: callerPoliciesJson }
            { name: 'APP_CONFIG_ENDPOINT', value: appConfiguration.properties.endpoint }
            { name: 'CALLER_POLICY_KEY', value: callerPolicyKey }
            { name: 'CALLER_POLICY_LABEL', value: callerPolicyLabel }
            { name: 'CALLER_POLICY_REFRESH_SECONDS', value: string(callerPolicyRefreshSeconds) }
            { name: 'CALLER_POLICY_MAX_STALENESS_SECONDS', value: string(callerPolicyMaxStalenessSeconds) }
            { name: 'REGISTRY_BACKEND', value: registryBackend }
            { name: 'REGISTRY_TABLE_ENDPOINT', value: registryBackend == 'table' ? 'https://${registryStorage.name}.table.${environment().suffixes.storage}' : '' }
            { name: 'REGISTRY_TABLE_NAME', value: 'InvestigationRegistry' }
            { name: 'ACTIVE_METADATA_RETENTION_SECONDS', value: string(activeMetadataRetentionDays * 86400) }
            { name: 'FINAL_FINDINGS_METADATA_RETENTION_SECONDS', value: string(finalFindingsMetadataRetentionDays * 86400) }
            { name: 'EXPIRY_CLEANUP_INTERVAL_SECONDS', value: string(expiryCleanupIntervalSeconds) }
            { name: 'MCP_ALLOWED_HOSTS', value: mcpAllowedHosts }
            { name: 'MCP_ENABLE_DNS_REBINDING_PROTECTION', value: mcpEnableDnsRebindingProtection }
            { name: 'PLATFORM_CIRCUIT_FAILURE_THRESHOLD', value: string(platformCircuitFailureThreshold) }
            { name: 'PLATFORM_CIRCUIT_RECOVERY_SECONDS', value: string(platformCircuitRecoverySeconds) }
          ]
        }
      ]
      scale: {
        minReplicas: registryBackend == 'memory' ? 1 : minReplicas
        maxReplicas: registryBackend == 'memory' ? 1 : maxReplicas
      }
    }
  }
}

resource registryTableContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (registryBackend == 'table') {
  name: guid(registryStorage.id, proxyUami.id, storageTableDataContributorRoleDefinitionId)
  scope: registryStorage
  properties: {
    principalId: proxyUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageTableDataContributorRoleDefinitionId)
    principalType: 'ServicePrincipal'
    description: 'Escalation proxy reads and updates investigation registry tables'
  }
}

// ── SRE Agent Administrator role on the platform agent ────────────────────────
// This grants the proxy's MI the SRE Agent Administrator (data-plane) role
// on the platform SRE Agent resource only.
// Built-in role: SRE Agent Administrator
// Role ID: check az role definition list --name "SRE Agent Administrator"
// This is a resource-scoped assignment.

// The 'SRE Agent Administrator' role GUID is supplied as a parameter so it is
// resolved at deploy time (see deploy-escalation-proxy.ps1) rather than hardcoded.
var sreAgentAdminRoleId = sreAgentAdminRoleDefinitionId

// Reference the platform agent resource to use as scope for the role assignment.
// The agent is in the same resource group as this template.
resource platformAgent 'Microsoft.App/agents@2026-01-01' existing = {
  name: last(split(platformAgentResourceId, '/'))
}

resource sreAgentAdminAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(platformAgentResourceId, proxyUami.id, sreAgentAdminRoleId)
  scope: platformAgent
  properties: {
    principalId: proxyUami.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sreAgentAdminRoleId)
    principalType: 'ServicePrincipal'
    description: 'Escalation proxy calls platform SRE agent data plane'
  }
}

// ── Outputs ──────────────────────────────────────────────────────────────────
@description('HTTPS URL of the escalation proxy MCP endpoint. The trailing slash avoids mount redirects for connector clients.')
output proxyEndpointUrl string = 'https://${proxyApp.properties.configuration.ingress.fqdn}/mcp/'

@description('Container App managed identity principal ID.')
output proxyPrincipalId string = proxyUami.properties.principalId

@description('Resource ID of the shared investigation registry storage account.')
output registryStorageAccountId string = registryBackend == 'table' ? registryStorage.id : ''

@description('Effective investigation registry backend for this deployment.')
output registryBackend string = registryBackend

@description('Azure App Configuration endpoint used for dynamic caller policy.')
output appConfigurationEndpoint string = appConfiguration.properties.endpoint

@description('Azure App Configuration store name used for dynamic caller policy.')
output appConfigurationName string = appConfiguration.name

@description('Run this command to grant a workload agent MI the EscalationCaller app role.')
output grantWorkloadAppRoleCommand string = 'az ad app role-assignment create --id <workload-agent-principal-id> --app-id ${entraAppClientId} --app-roles EscalationCaller'
