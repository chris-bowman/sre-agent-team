targetScope = 'resourceGroup'

@description('Name of the escalation proxy Container App.')
param proxyAppName string = 'sre-escalation-proxy'

@description('Azure region for the alert rules.')
param location string = resourceGroup().location

@description('Name of the Log Analytics workspace receiving the proxy console logs.')
param logAnalyticsWorkspaceName string = '${proxyAppName}-logs'

@description('Resource ID of an existing Azure Monitor action group. Leave empty to deploy detection without notifications.')
param alertActionGroupResourceId string = ''

@description('Whether the outage alert rules are enabled.')
param alertsEnabled bool = true

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

var proxyLogScope = 'ContainerAppConsoleLogs_CL | where ContainerAppName_s == "${proxyAppName}"'

resource policyAndReadinessAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${proxyAppName}-policy-readiness'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${proxyAppName} policy and readiness failures'
    description: 'Detects caller-policy refresh failures and failed dependency readiness checks.'
    enabled: alertsEnabled
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    scopes: [logAnalytics.id]
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
    criteria: {
      allOf: [
        {
          query: '${proxyLogScope} | where Log_s has_any (\'"event": "caller_policy_refresh_failed"\', \'"event": "readiness_check_failed"\')'
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: empty(alertActionGroupResourceId) ? null : {
      actionGroups: [alertActionGroupResourceId]
      customProperties: {
        service: proxyAppName
        category: 'policy-or-readiness'
      }
    }
  }
}

resource platformDependencyAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${proxyAppName}-platform-dependency'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${proxyAppName} platform dependency failures'
    description: 'Detects an open Platform SRE Agent circuit or exhausted platform request retries.'
    enabled: alertsEnabled
    severity: 1
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    scopes: [logAnalytics.id]
    autoMitigate: true
    checkWorkspaceAlertsStorageConfigured: false
    criteria: {
      allOf: [
        {
          query: '${proxyLogScope} | where Log_s has_any (\'"event": "platform_circuit_opened"\', \'"event": "platform_request_failed"\')'
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: empty(alertActionGroupResourceId) ? null : {
      actionGroups: [alertActionGroupResourceId]
      customProperties: {
        service: proxyAppName
        category: 'platform-dependency'
      }
    }
  }
}

output policyAndReadinessAlertName string = policyAndReadinessAlert.name
output platformDependencyAlertName string = platformDependencyAlert.name
output notificationsConfigured bool = !empty(alertActionGroupResourceId)
