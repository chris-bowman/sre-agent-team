using './main.bicep'

// ============================================================
// Workload SRE Agent — Parameters Template
// Each application team fills in their own copy of this file.
// ============================================================

// Unique name for this workload agent. Use your app/team name. e.g. 'sre-payments-api'
param agentName = '<FILL_IN: e.g. sre-payments-api>'

// Friendly display name shown in the portal and in escalation messages.
param workloadDisplayName = '<FILL_IN: e.g. Payments API Team>'

// Azure region. Must match the region of your application resources.
// If you deploy via scripts/deploy-workload.ps1, -Location overrides this value.
param location = '<FILL_IN: e.g. australiaeast>'

// Comma-separated list of resource group names this agent owns.
// The agent will only investigate resources in these groups.
param scopedResourceGroups = '<FILL_IN: e.g. rg-payments-api-prod, rg-payments-api-shared>'

// From escalation-proxy/infrastructure/main.bicep output: proxyEndpointUrl
param escalationProxyEndpointUrl = '<FILL_IN: https://sre-escalation-proxy.*.azurecontainerapps.io/mcp>'

// Entra app client ID of the proxy — from deploy-escalation-proxy.ps1 output.
// Workload agent uses this to acquire a correctly-scoped token for the proxy.
param escalationProxyEntraClientId = '<FILL_IN: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx>'
