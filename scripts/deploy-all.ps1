# scripts/deploy-all.ps1
# End-to-end orchestrator for the two-tier SRE Agent team.
#
# Runs all four phases in order, automatically passing outputs between them via
# the shared deploy-state file (scripts/.deploy-state.json):
#
#   1. platform  -> deploy-platform.ps1            (Platform SRE Agent + RBAC + custom agent)
#   2. proxy     -> deploy-escalation-proxy.ps1    (Entra app + Container App proxy)
#   3. workload  -> deploy-workload.ps1            (Workload SRE Agent + MCP connector + custom agent)
#   4. grant     -> grant-workload-escalation.ps1  (EscalationCaller app-role for the workload MI)
#
# You can still run each phase script on its own — they read prior outputs from
# the same state file. Use -Phases to run a subset (handy for resuming).
#
# Example (single subscription lab):
#   .\scripts\deploy-all.ps1 `
#       -PlatformSubscriptionId <sub> -PlatformResourceGroup rg-sre-platform `
#       -WorkloadSubscriptionId <sub> -WorkloadResourceGroup rg-sre-payments `
#       -AcrName myacr `
#       -WorkloadAgentName sre-payments-api -WorkloadDisplayName 'Payments API' `
#       -ScopedResourceGroups 'rg-payments-api-prod' `
#       -Location australiaeast
#
# Example (resume from the workload phase only):
#   .\scripts\deploy-all.ps1 ... -Phases workload,grant

[CmdletBinding()]
param (
    # ── Platform phase ──
    [Parameter(Mandatory)] [string] $PlatformSubscriptionId,
    [Parameter(Mandatory)] [string] $PlatformResourceGroup,
    [string] $PlatformManagementGroupId = '',
    [string] $PlatformAgentName = 'sre-platform',

    # ── Proxy phase ──
    [Parameter(Mandatory)] [string] $AcrName,
    [string] $ProxyAppName = 'sre-escalation-proxy',
    [ValidateSet('table', 'memory')] [string] $RegistryBackend = 'table',
    [ValidateRange(1, 100)] [int] $ProxyMinReplicas = 1,
    [ValidateRange(1, 100)] [int] $ProxyMaxReplicas = 5,
    [string] $AppConfigurationName = '',
    [string] $CallerPolicyKey = 'escalation/caller-policies',
    [string] $CallerPolicyLabel = 'production',
    [ValidateRange(1, 3600)] [int] $CallerPolicyRefreshSeconds = 30,
    [ValidateRange(1, 86400)] [int] $CallerPolicyMaxStalenessSeconds = 300,
    [switch] $EnablePrivateNetworking,
    [string] $PrivateNetworkName = '',
    [string] $PrivateNetworkAddressPrefix = '10.42.0.0/16',
    [string] $ContainerEnvironmentSubnetPrefix = '10.42.0.0/27',
    [string] $StoragePrivateEndpointSubnetPrefix = '10.42.1.0/28',
    [ValidateSet('true', 'false')] [string] $McpEnableDnsRebindingProtection = 'true',

    # ── Workload phase ──
    [string] $WorkloadSubscriptionId = '',
    [string] $WorkloadResourceGroup = '',
    [string] $WorkloadAgentName = '',
    [string] $WorkloadDisplayName = '',
    [string] $ScopedResourceGroups = '',

    # ── Shared ──
    [string] $Location = 'australiaeast',
    [switch] $EnableApplicationInsights,
    [ValidateSet('platform', 'proxy', 'workload', 'grant')]
    [string[]] $Phases = @('platform', 'proxy', 'workload', 'grant'),
    [switch] $ResetState,
    [switch] $SkipCustomAgentUpload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

# Default the workload subscription/RG to the platform ones (single-subscription lab).
if ([string]::IsNullOrWhiteSpace($WorkloadSubscriptionId)) { $WorkloadSubscriptionId = $PlatformSubscriptionId }
if ([string]::IsNullOrWhiteSpace($WorkloadResourceGroup))  { $WorkloadResourceGroup  = "rg-sre-$WorkloadAgentName" }

$runWorkload = $Phases -contains 'workload' -or $Phases -contains 'grant'
if ($runWorkload) {
    foreach ($p in @{ WorkloadAgentName = $WorkloadAgentName; WorkloadDisplayName = $WorkloadDisplayName; ScopedResourceGroups = $ScopedResourceGroups }.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace($p.Value)) {
            throw "The '$($p.Key)' parameter is required when running the workload or grant phase."
        }
    }
}

if ($ResetState) {
    $statePath = Get-DeployStatePath
    if (Test-Path $statePath) {
        Remove-Item $statePath -Force
        Write-Host "Cleared previous deploy state: $statePath" -ForegroundColor Yellow
    }
}

$banner = {
    param($Text)
    Write-Host ''
    Write-Host ('#' * 72) -ForegroundColor Magenta
    Write-Host "#  $Text" -ForegroundColor Magenta
    Write-Host ('#' * 72) -ForegroundColor Magenta
}

# ── Phase 1: Platform ─────────────────────────────────────────────────────────
if ($Phases -contains 'platform') {
    & $banner 'PHASE 1/4 — Platform SRE Agent'
    $platformArgs = @{
        ResourceGroup             = $PlatformResourceGroup
        SubscriptionId            = $PlatformSubscriptionId
        PlatformManagementGroupId = $PlatformManagementGroupId
        AgentName                 = $PlatformAgentName
        Location                  = $Location
    }
    if ($EnableApplicationInsights) { $platformArgs.EnableApplicationInsights = $true }
    if ($SkipCustomAgentUpload) { $platformArgs.SkipCustomAgentUpload = $true }
    $null = & "$PSScriptRoot\deploy-platform.ps1" @platformArgs
}

# ── Phase 2: Escalation proxy ─────────────────────────────────────────────────
if ($Phases -contains 'proxy') {
    & $banner 'PHASE 2/4 — Escalation Proxy (Container App + Entra app)'
    $proxyArgs = @{
        ResourceGroup   = $PlatformResourceGroup
        SubscriptionId  = $PlatformSubscriptionId
        AcrName         = $AcrName
        ProxyAppName    = $ProxyAppName
        Location        = $Location
        RegistryBackend = $RegistryBackend
        MinReplicas     = $ProxyMinReplicas
        MaxReplicas     = $ProxyMaxReplicas
        AppConfigurationName = $AppConfigurationName
        CallerPolicyKey = $CallerPolicyKey
        CallerPolicyLabel = $CallerPolicyLabel
        CallerPolicyRefreshSeconds = $CallerPolicyRefreshSeconds
        CallerPolicyMaxStalenessSeconds = $CallerPolicyMaxStalenessSeconds
        PrivateNetworkName = $PrivateNetworkName
        PrivateNetworkAddressPrefix = $PrivateNetworkAddressPrefix
        ContainerEnvironmentSubnetPrefix = $ContainerEnvironmentSubnetPrefix
        StoragePrivateEndpointSubnetPrefix = $StoragePrivateEndpointSubnetPrefix
        McpEnableDnsRebindingProtection = $McpEnableDnsRebindingProtection
        # PlatformAgentId / PlatformAgentEndpoint are read from deploy state.
    }
    if ($EnablePrivateNetworking) { $proxyArgs.EnablePrivateNetworking = $true }
    $null = & "$PSScriptRoot\deploy-escalation-proxy.ps1" @proxyArgs
}

# ── Phase 3: Workload agent ───────────────────────────────────────────────────
if ($Phases -contains 'workload') {
    & $banner 'PHASE 3/4 — Workload SRE Agent'
    $workloadArgs = @{
        ResourceGroup        = $WorkloadResourceGroup
        SubscriptionId       = $WorkloadSubscriptionId
        AgentName            = $WorkloadAgentName
        WorkloadDisplayName  = $WorkloadDisplayName
        ScopedResourceGroups = $ScopedResourceGroups
        Location             = $Location
        # EscalationProxy* values are read from deploy state.
    }
    if ($EnableApplicationInsights) { $workloadArgs.EnableApplicationInsights = $true }
    if ($SkipCustomAgentUpload) { $workloadArgs.SkipCustomAgentUpload = $true }
    $null = & "$PSScriptRoot\deploy-workload.ps1" @workloadArgs
}

# ── Phase 4: Grant escalation app role ────────────────────────────────────────
if ($Phases -contains 'grant') {
    & $banner 'PHASE 4/4 — Grant EscalationCaller app role'
    # Platform subscription context is required for the Entra/Graph call.
    az account set --subscription $PlatformSubscriptionId | Out-Null
    $null = & "$PSScriptRoot\grant-workload-escalation.ps1" `
        -WorkloadName $WorkloadAgentName `
        -SubscriptionId $PlatformSubscriptionId `
        -ResourceGroup $PlatformResourceGroup `
        -ProxyAppName $ProxyAppName

    if ($Phases -contains 'workload') {
        & $banner 'FINALIZATION — Refresh and wait for MCP connector'
        $state = Get-DeployState
        Sync-McpConnectorEnvelope `
            -SubscriptionId $WorkloadSubscriptionId `
            -ResourceGroup $WorkloadResourceGroup `
            -AgentName $WorkloadAgentName `
            -ConnectorName 'platform-escalation-mi' `
            -EndpointUrl $state.ProxyEndpointUrl `
            -ArmScope "api://$($state.ProxyEntraClientId)/.default"

        $connectorConnected = Wait-McpConnectorConnected `
            -AgentEndpoint $state.WorkloadAgentEndpoint `
            -ConnectorName 'platform-escalation-mi' `
            -MaxAttempts 60 `
            -DelaySeconds 15
        if (-not $connectorConnected) {
            throw 'MCP connector did not become healthy within the 15-minute post-grant readiness window.'
        }
    }
}

& $banner 'All requested phases complete'
Write-Host "Deploy state: $(Get-DeployStatePath)" -ForegroundColor Green
$state = Get-DeployState
if ($state) {
    $state | Format-List | Out-String | Write-Host
}
Write-Host 'Test the escalation path in the workload SRE Agent chat:' -ForegroundColor Cyan
Write-Host '  /agent platform-escalation'
Write-Host '  Test the escalation path by creating a dummy investigation, severity "low".'
