# scripts/grant-workload-escalation.ps1
# Compatibility wrapper for existing workload-oriented deployment commands.

[CmdletBinding(SupportsShouldProcess)]
param (
    [string] $WorkloadPrincipalId = '',
    [string] $EntraAppId = '',
    [string] $WorkloadName = '',
    [string] $SubscriptionId = '',
    [string] $ResourceGroup = '',
    [string] $ProxyAppName = '',
    [ValidateSet('low', 'medium', 'high', 'critical')]
    [string] $MaximumSeverity = 'critical',
    [ValidateRange(1, 100)]
    [int] $MaximumConcurrentInvestigations = 10,
    [string[]] $AllowedResourceGroup = @(),
    [switch] $UpdateExistingPolicy,
    [switch] $SkipPolicyUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

$resolvedSubscriptionId = Resolve-Value -Provided $SubscriptionId -StateKey 'ProxySubscriptionId'
$resolvedResourceGroup = Resolve-Value -Provided $ResourceGroup -StateKey 'ProxyResourceGroup'
$resolvedProxyAppName = Resolve-Value -Provided $ProxyAppName -StateKey 'ProxyAppName'
if (-not $SkipPolicyUpdate -and (
        [string]::IsNullOrWhiteSpace($resolvedResourceGroup) -or [string]::IsNullOrWhiteSpace($resolvedProxyAppName)
    )) {
    throw 'Proxy resource coordinates are unavailable. Redeploy the proxy, pass -ResourceGroup and -ProxyAppName, or explicitly use -SkipPolicyUpdate for a role-only compatibility grant.'
}

$primaryPrincipalId = Resolve-Value -Provided $WorkloadPrincipalId -StateKey 'WorkloadAgentUamiPrincipal'
if ([string]::IsNullOrWhiteSpace($primaryPrincipalId)) {
    $primaryPrincipalId = Resolve-Value -Provided '' -StateKey 'WorkloadAgentPrincipal'
}
$systemAssignedPrincipalId = Resolve-Value -Provided '' -StateKey 'WorkloadAgentPrincipal'
$principalIds = @(
    @($primaryPrincipalId, $systemAssignedPrincipalId) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
)
if ($principalIds.Count -eq 0) {
    throw 'WorkloadPrincipalId is required. Pass it explicitly or deploy the workload agent first.'
}
if (-not $SkipPolicyUpdate -and $AllowedResourceGroup.Count -eq 0 -and -not $UpdateExistingPolicy) {
    throw 'AllowedResourceGroup is required for new caller onboarding. Pass the workload-owned resource group name or canonical ID.'
}

foreach ($principalId in $principalIds) {
    $arguments = @{
        Operation         = 'Grant'
        CallerPrincipalId = $principalId
        EntraAppId        = $EntraAppId
        SubscriptionId    = $resolvedSubscriptionId
        ResourceGroup     = $resolvedResourceGroup
        ProxyAppName      = $resolvedProxyAppName
        AllowedResourceGroup = $AllowedResourceGroup
        SkipPolicyUpdate  = $SkipPolicyUpdate
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkloadName)) { $arguments.CallerDisplayName = $WorkloadName }
    if ($PSBoundParameters.ContainsKey('MaximumSeverity')) { $arguments.MaximumSeverity = $MaximumSeverity }
    if ($PSBoundParameters.ContainsKey('MaximumConcurrentInvestigations')) {
        $arguments.MaximumConcurrentInvestigations = $MaximumConcurrentInvestigations
    }
    if ($UpdateExistingPolicy) { $arguments.UpdateExistingPolicy = $true }
    if ($WhatIfPreference) { $arguments.WhatIf = $true }

    & "$PSScriptRoot\manage-escalation-callers.ps1" @arguments
}
