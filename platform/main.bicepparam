using './main.bicep'

// ============================================================
// Platform SRE Agent — Parameters
// Fill in values for your environment before deploying.
// ============================================================

// Name of the SRE Agent resource. Must be unique within the subscription.
param agentName = 'sre-platform'

// Azure region. SRE Agent is available in select regions — check:
// https://learn.microsoft.com/en-us/azure/sre-agent/supported-regions
// If you deploy via scripts/deploy-platform.ps1, -Location overrides this value.
param location = '<FILL_IN: e.g. australiaeast>'

// Optional ALZ Platform management group ID.
// Leave empty for single-subscription or test deployments.
// Run: az account management-group list --query "[].{name:name, displayName:displayName}"
param platformManagementGroupId = ''
