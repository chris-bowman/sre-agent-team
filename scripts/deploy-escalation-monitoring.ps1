[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [string] $ProxyAppName = 'sre-escalation-proxy',
    [string] $LogAnalyticsWorkspaceName = '',
    [string] $AlertActionGroupResourceId = '',
    [bool] $AlertsEnabled = $true,
    [string] $Location = 'australiaeast'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($LogAnalyticsWorkspaceName)) {
    $LogAnalyticsWorkspaceName = "$ProxyAppName-logs"
}

if (-not [string]::IsNullOrWhiteSpace($AlertActionGroupResourceId) -and
    $AlertActionGroupResourceId -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Insights/actionGroups/[^/]+$') {
    throw 'AlertActionGroupResourceId must be a complete Microsoft.Insights/actionGroups resource ID.'
}

$deploymentName = "${ProxyAppName}-monitoring-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"
$outputs = az deployment group create `
    --name $deploymentName `
    --resource-group $ResourceGroup `
    --subscription $SubscriptionId `
    --template-file "$PSScriptRoot\..\escalation-proxy\infrastructure\monitoring.bicep" `
    --parameters `
        proxyAppName=$ProxyAppName `
        logAnalyticsWorkspaceName=$LogAnalyticsWorkspaceName `
        alertActionGroupResourceId=$AlertActionGroupResourceId `
        alertsEnabled=$($AlertsEnabled.ToString().ToLowerInvariant()) `
        location=$Location `
    --query properties.outputs `
    --output json
if ($LASTEXITCODE -ne 0) {
    throw 'Escalation monitoring deployment failed. Review the Azure deployment error above.'
}

$outputs | ConvertFrom-Json