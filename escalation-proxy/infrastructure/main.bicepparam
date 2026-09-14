using './main.bicep'

// ============================================================
// Platform Escalation Proxy — Parameters
// Platform team fills these in. Deploy AFTER platform/main.bicep.
// ============================================================

param proxyAppName = 'sre-escalation-proxy'
// Azure region for the Container App and related resources.
// If you deploy via scripts/deploy-escalation-proxy.ps1, -Location overrides this value.
param location = '<FILL_IN: e.g. australiaeast>'

// Immutable container image — build from escalation-proxy/app/, push to ACR,
// and resolve the manifest digest. See scripts/deploy-escalation-proxy.ps1.
param containerImage = '<FILL_IN: e.g. myregistry.azurecr.io/sre-escalation-proxy@sha256:...>'

// From platform/main.bicep outputs: agentId
param platformAgentResourceId = '<FILL_IN: /subscriptions/.../Microsoft.App/agents/sre-platform>'

// From platform/main.bicep outputs: agentEndpoint
param platformAgentEndpoint = '<FILL_IN: https://sre-platform.abc123.azuresre.ai>'

// Your Azure tenant ID
param tenantId = '<FILL_IN>'

// Entra app registration client ID — created in deploy-escalation-proxy.ps1 step 1
param entraAppClientId = '<FILL_IN>'

// Built-in "SRE Agent Administrator" role definition GUID.
// deploy-escalation-proxy.ps1 resolves and passes this automatically.
// To deploy this template directly, resolve it with:
//   az role definition list --name "SRE Agent Administrator" --query "[0].name" -o tsv
param sreAgentAdminRoleDefinitionId = '<FILL_IN: GUID from az role definition list>'

// Built-in "Storage Table Data Contributor" role definition GUID.
// deploy-escalation-proxy.ps1 resolves and passes this automatically.
param storageTableDataContributorRoleDefinitionId = '<FILL_IN: GUID from az role definition list>'

// Investigation registry backend: 'table' (Azure Table Storage) or 'memory'.
// Table mode uses the private networking profile by default. Use 'memory' for
// local or non-production smoke tests without shared Table infrastructure.
// deploy-escalation-proxy.ps1 -RegistryBackend overrides this value.
param registryBackend = 'table'

// ACR login server for the Container App registries config (e.g. myregistry.azurecr.io)
// deploy-escalation-proxy.ps1 resolves and passes this automatically.
param acrLoginServer = '<FILL_IN: e.g. myregistry.azurecr.io>'
