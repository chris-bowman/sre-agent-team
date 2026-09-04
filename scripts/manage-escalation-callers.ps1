# scripts/manage-escalation-callers.ps1
# Platform-owned administration for same-tenant escalation callers.

[CmdletBinding(SupportsShouldProcess)]
param (
    [ValidateSet('Grant', 'List', 'Verify', 'Disable', 'Revoke')]
    [string] $Operation = 'List',
    [Alias('WorkloadPrincipalId')]
    [string] $CallerPrincipalId = '',
    [Alias('WorkloadName')]
    [string] $CallerDisplayName = '',
    [string] $EntraAppId = '',
    [string] $SubscriptionId = '',
    [string] $ResourceGroup = '',
    [string] $ProxyAppName = '',
    [ValidateSet('low', 'medium', 'high', 'critical')]
    [string] $MaximumSeverity = 'critical',
    [ValidateRange(1, 100)]
    [int] $MaximumConcurrentInvestigations = 10,
    [switch] $UpdateExistingPolicy,
    [switch] $SkipPolicyUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

$maximumSeveritySpecified = $PSBoundParameters.ContainsKey('MaximumSeverity')
$maximumConcurrencySpecified = $PSBoundParameters.ContainsKey('MaximumConcurrentInvestigations')
$displayNameSpecified = $PSBoundParameters.ContainsKey('CallerDisplayName') -or $PSBoundParameters.ContainsKey('WorkloadName')

function Invoke-AzJson {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [ValidateRange(1, 5)] [int] $MaximumAttempts = 3
    )

    $errorFile = [System.IO.Path]::GetTempFileName()
    try {
        for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
            $json = & az @Arguments --output json 2> $errorFile
            if ($LASTEXITCODE -eq 0) {
                if ([string]::IsNullOrWhiteSpace($json)) { return $null }
                return $json | ConvertFrom-Json
            }
            if ($attempt -lt $MaximumAttempts) {
                Start-Sleep -Seconds ([math]::Pow(2, $attempt - 1))
            }
        }

        $details = Get-Content -Path $errorFile -Raw -ErrorAction SilentlyContinue
        throw "Azure CLI command failed after $MaximumAttempts attempts: az $($Arguments -join ' '). $details"
    } finally {
        Remove-Item $errorFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-GraphWrite {
    param(
        [Parameter(Mandatory)] [ValidateSet('POST', 'PATCH')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [object] $Body
    )

    $temporaryFile = [System.IO.Path]::GetTempFileName() + '.json'
    try {
        $json = $Body | ConvertTo-Json -Depth 20 -Compress
        [System.IO.File]::WriteAllText($temporaryFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        & az rest --method $Method --uri $Uri --headers 'Content-Type=application/json' --body "@$temporaryFile" --output none
        if ($LASTEXITCODE -ne 0) {
            throw "Microsoft Graph $Method failed for $Uri."
        }
    } finally {
        Remove-Item $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-EscalationAppRole {
    param(
        [Parameter(Mandatory)] [string] $ApplicationId,
        [Parameter(Mandatory)] [bool] $CreateIfMissing
    )

    $application = Invoke-AzJson -Arguments @('ad', 'app', 'show', '--id', $ApplicationId)
    $role = @($application.appRoles | Where-Object value -eq 'EscalationCaller') | Select-Object -First 1
    if ($null -ne $role) { return $role }
    if (-not $CreateIfMissing) {
        throw "EscalationCaller app role not found on app $ApplicationId."
    }

    $newRole = [pscustomobject]@{
        allowedMemberTypes = @('Application')
        description        = 'Allows an approved same-tenant caller to request platform investigations'
        displayName        = 'EscalationCaller'
        id                 = [guid]::NewGuid().ToString()
        isEnabled          = $true
        value              = 'EscalationCaller'
    }
    if (-not $PSCmdlet.ShouldProcess($ApplicationId, 'Create EscalationCaller app role')) {
        return $newRole
    }

    $roles = @($application.appRoles)
    $roles += $newRole
    Invoke-GraphWrite -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($application.id)" -Body @{ appRoles = $roles }

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $application = Invoke-AzJson -Arguments @('ad', 'app', 'show', '--id', $ApplicationId)
        $role = @($application.appRoles | Where-Object value -eq 'EscalationCaller') | Select-Object -First 1
        if ($null -ne $role) { return $role }
        if ($attempt -lt 5) { Start-Sleep -Seconds 2 }
    }
    if ($null -eq $role) {
        throw "EscalationCaller app role was not visible after creation on app $ApplicationId."
    }
}

function Get-RoleAssignments {
    param(
        [Parameter(Mandatory)] [string] $ProxyServicePrincipalId,
        [Parameter(Mandatory)] [string] $AppRoleId
    )

    $assignments = @()
    $nextLink = "https://graph.microsoft.com/v1.0/servicePrincipals/$ProxyServicePrincipalId/appRoleAssignedTo"
    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        $response = Invoke-AzJson -Arguments @('rest', '--method', 'GET', '--uri', $nextLink)
        $assignments += @($response.value | Where-Object appRoleId -eq $AppRoleId)
        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        $nextLink = if ($null -ne $nextLinkProperty) { $nextLinkProperty.Value } else { $null }
    }
    return $assignments
}

function Get-CallerServicePrincipal {
    param([Parameter(Mandatory)] [string] $PrincipalId)

    return Invoke-AzJson -Arguments @('ad', 'sp', 'show', '--id', $PrincipalId)
}

function Get-CallerPolicies {
    if ($SkipPolicyUpdate) { return @() }

    $arguments = @(
        'containerapp', 'show', '--name', $ProxyAppName,
        '--resource-group', $ResourceGroup
    )
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $arguments += @('--subscription', $SubscriptionId)
    }
    $containerApp = Invoke-AzJson -Arguments $arguments
    $policyEnvironmentVariable = @(
        $containerApp.properties.template.containers[0].env |
            Where-Object name -eq 'CALLER_POLICIES_JSON'
    ) | Select-Object -First 1
    if ($null -eq $policyEnvironmentVariable -or [string]::IsNullOrWhiteSpace($policyEnvironmentVariable.value)) {
        return @()
    }

    $policies = $policyEnvironmentVariable.value | ConvertFrom-Json
    return @($policies)
}

function Set-CallerPolicies {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies)

    if ($SkipPolicyUpdate) { return }
    $json = ConvertTo-Json -InputObject @($Policies) -Depth 10 -Compress
    $escapedJson = $json.Replace('"', '\"')
    $arguments = @(
        'containerapp', 'update', '--name', $ProxyAppName,
        '--resource-group', $ResourceGroup,
        '--set-env-vars', "CALLER_POLICIES_JSON=$escapedJson",
        '--output', 'none'
    )
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $arguments += @('--subscription', $SubscriptionId)
    }
    & az @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to update CALLER_POLICIES_JSON on the escalation proxy.'
    }
}

function New-CallerPolicy {
    param(
        [Parameter(Mandatory)] [object] $ServicePrincipal,
        [Parameter(Mandatory)] [bool] $Enabled,
        [string] $Severity = 'critical',
        [int] $Quota = 10,
        [string] $DisplayName = ''
    )

    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $ServicePrincipal.displayName }
    return [pscustomobject][ordered]@{
        appid                             = $ServicePrincipal.appId
        display_name                      = $DisplayName
        enabled                           = $Enabled
        maximum_severity                  = $Severity
        maximum_concurrent_investigations = $Quota
    }
}

function Initialize-CallerPolicies {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies,
        [Parameter(Mandatory)] [object[]] $Assignments
    )

    if ($Policies.Count -gt 0 -or $SkipPolicyUpdate) { return @($Policies) }

    $initialized = @()
    foreach ($assignment in $Assignments) {
        $servicePrincipal = Get-CallerServicePrincipal -PrincipalId $assignment.principalId
        $initialized += New-CallerPolicy -ServicePrincipal $servicePrincipal -Enabled $true
    }
    return $initialized
}

$EntraAppId = Resolve-Value -Provided $EntraAppId -StateKey 'ProxyEntraClientId'
$SubscriptionId = Resolve-Value -Provided $SubscriptionId -StateKey 'ProxySubscriptionId'
$ResourceGroup = Resolve-Value -Provided $ResourceGroup -StateKey 'ProxyResourceGroup'
$ProxyAppName = Resolve-Value -Provided $ProxyAppName -StateKey 'ProxyAppName'

if ([string]::IsNullOrWhiteSpace($EntraAppId)) {
    throw 'EntraAppId is required. Pass it explicitly or deploy the escalation proxy first.'
}
if (-not $SkipPolicyUpdate -and (
        [string]::IsNullOrWhiteSpace($ResourceGroup) -or [string]::IsNullOrWhiteSpace($ProxyAppName)
    )) {
    throw 'ResourceGroup and ProxyAppName are required for caller policy administration.'
}
if ($Operation -eq 'Disable' -and $SkipPolicyUpdate) {
    throw 'Disable requires caller policy administration; remove -SkipPolicyUpdate and provide the proxy resource coordinates.'
}

$requiresCaller = $Operation -in @('Grant', 'Verify', 'Disable', 'Revoke')
if ($requiresCaller) {
    $CallerPrincipalId = Resolve-Value -Provided $CallerPrincipalId -StateKey 'WorkloadAgentUamiPrincipal'
    if ([string]::IsNullOrWhiteSpace($CallerPrincipalId)) {
        throw "CallerPrincipalId is required for operation '$Operation'."
    }
}

$proxyServicePrincipal = Invoke-AzJson -Arguments @('ad', 'sp', 'show', '--id', $EntraAppId)
$appRole = Get-EscalationAppRole -ApplicationId $EntraAppId -CreateIfMissing ($Operation -eq 'Grant')
$assignments = @(Get-RoleAssignments -ProxyServicePrincipalId $proxyServicePrincipal.id -AppRoleId $appRole.id)
$policies = @(Get-CallerPolicies)

if ($Operation -eq 'List') {
    $results = @()
    foreach ($assignment in $assignments) {
        $servicePrincipal = Get-CallerServicePrincipal -PrincipalId $assignment.principalId
        $policy = @($policies | Where-Object appid -eq $servicePrincipal.appId) | Select-Object -First 1
        $results += [pscustomobject]@{
            display_name = $servicePrincipal.displayName
            appid = $servicePrincipal.appId
            principal_id = $servicePrincipal.id
            role_assigned = $true
            policy_registered = $null -ne $policy
            enabled = if ($null -ne $policy) { $policy.enabled } else { $policies.Count -eq 0 }
            maximum_severity = if ($null -ne $policy) { $policy.maximum_severity } else { $null }
            maximum_concurrent_investigations = if ($null -ne $policy) { $policy.maximum_concurrent_investigations } else { $null }
        }
    }
    foreach ($policy in $policies) {
        if (-not @($results | Where-Object appid -eq $policy.appid)) {
            $results += [pscustomobject]@{
                display_name = $policy.display_name
                appid = $policy.appid
                principal_id = $null
                role_assigned = $false
                policy_registered = $true
                enabled = $policy.enabled
                maximum_severity = $policy.maximum_severity
                maximum_concurrent_investigations = $policy.maximum_concurrent_investigations
            }
        }
    }
    $results | Sort-Object display_name, appid
    return
}

$callerServicePrincipal = Get-CallerServicePrincipal -PrincipalId $CallerPrincipalId
$callerAssignments = @($assignments | Where-Object principalId -eq $callerServicePrincipal.id)
$callerPolicy = @($policies | Where-Object appid -eq $callerServicePrincipal.appId) | Select-Object -First 1

if ($Operation -eq 'Verify') {
    $policyAllowsCaller = $policies.Count -eq 0 -or ($null -ne $callerPolicy -and $callerPolicy.enabled)
    $result = [pscustomobject]@{
        display_name = $callerServicePrincipal.displayName
        appid = $callerServicePrincipal.appId
        principal_id = $callerServicePrincipal.id
        role_assigned = $callerAssignments.Count -gt 0
        policy_registered = $null -ne $callerPolicy
        policy_mode = if ($policies.Count -eq 0) { 'permissive' } else { 'allowlist' }
        enabled = $policyAllowsCaller
    }
    $result
    if (-not $result.role_assigned -or -not $result.enabled) {
        throw "Caller '$($callerServicePrincipal.displayName)' is not authorized for escalation."
    }
    return
}

if ($Operation -eq 'Grant') {
    $policies = @(Initialize-CallerPolicies -Policies $policies -Assignments $assignments)
    if ($null -eq $callerPolicy -or $UpdateExistingPolicy) {
        $severity = if ($null -ne $callerPolicy -and -not $maximumSeveritySpecified) { $callerPolicy.maximum_severity } else { $MaximumSeverity }
        $quota = if ($null -ne $callerPolicy -and -not $maximumConcurrencySpecified) { $callerPolicy.maximum_concurrent_investigations } else { $MaximumConcurrentInvestigations }
        $displayName = if ($null -ne $callerPolicy -and -not $displayNameSpecified) { $callerPolicy.display_name } else { $CallerDisplayName }
        $policies = @($policies | Where-Object appid -ne $callerServicePrincipal.appId)
        $policies += New-CallerPolicy `
            -ServicePrincipal $callerServicePrincipal `
            -Enabled $true `
            -Severity $severity `
            -Quota $quota `
            -DisplayName $displayName
        if ($PSCmdlet.ShouldProcess($ProxyAppName, "Enable caller policy for $($callerServicePrincipal.appId)")) {
            Set-CallerPolicies -Policies $policies
        }
    }
    if ($callerAssignments.Count -eq 0 -and $PSCmdlet.ShouldProcess($callerServicePrincipal.displayName, 'Grant EscalationCaller app role')) {
        Invoke-GraphWrite -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($proxyServicePrincipal.id)/appRoleAssignedTo" `
            -Body @{
                principalId = $callerServicePrincipal.id
                resourceId = $proxyServicePrincipal.id
                appRoleId = $appRole.id
            }
    }
    if ($WhatIfPreference) {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' grant was evaluated; no changes were applied." -ForegroundColor Yellow
    } elseif ($null -ne $callerPolicy -and -not $UpdateExistingPolicy) {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' role is granted; existing policy was preserved." -ForegroundColor Green
    } else {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' is granted and enabled." -ForegroundColor Green
    }
    return
}

if ($Operation -eq 'Disable') {
    $policies = @(Initialize-CallerPolicies -Policies $policies -Assignments $assignments)
    $policies = @($policies | Where-Object appid -ne $callerServicePrincipal.appId)
    $policies += New-CallerPolicy `
        -ServicePrincipal $callerServicePrincipal `
        -Enabled $false `
        -Severity $(if ($null -ne $callerPolicy) { $callerPolicy.maximum_severity } else { $MaximumSeverity }) `
        -Quota $(if ($null -ne $callerPolicy) { $callerPolicy.maximum_concurrent_investigations } else { $MaximumConcurrentInvestigations }) `
        -DisplayName $(if ($null -ne $callerPolicy) { $callerPolicy.display_name } else { $CallerDisplayName })
    if ($PSCmdlet.ShouldProcess($ProxyAppName, "Disable caller policy for $($callerServicePrincipal.appId)")) {
        Set-CallerPolicies -Policies $policies
    }
    if ($WhatIfPreference) {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' disable was evaluated; no changes were applied." -ForegroundColor Yellow
    } else {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' is disabled; its Entra assignment is retained." -ForegroundColor Yellow
    }
    return
}

if ($Operation -eq 'Revoke') {
    $policies = @(Initialize-CallerPolicies -Policies $policies -Assignments $assignments)
    foreach ($assignment in $callerAssignments) {
        if ($PSCmdlet.ShouldProcess($callerServicePrincipal.displayName, 'Remove EscalationCaller app role')) {
            & az rest --method DELETE `
                --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($proxyServicePrincipal.id)/appRoleAssignedTo/$($assignment.id)" `
                --output none
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to remove app-role assignment $($assignment.id)."
            }
        }
    }
    $policies = @($policies | Where-Object appid -ne $callerServicePrincipal.appId)
    $policies += New-CallerPolicy `
        -ServicePrincipal $callerServicePrincipal `
        -Enabled $false `
        -Severity $(if ($null -ne $callerPolicy) { $callerPolicy.maximum_severity } else { $MaximumSeverity }) `
        -Quota $(if ($null -ne $callerPolicy) { $callerPolicy.maximum_concurrent_investigations } else { $MaximumConcurrentInvestigations }) `
        -DisplayName $(if ($null -ne $callerPolicy) { $callerPolicy.display_name } else { $CallerDisplayName })
    if ($PSCmdlet.ShouldProcess($ProxyAppName, "Retain disabled caller tombstone for $($callerServicePrincipal.appId)")) {
        Set-CallerPolicies -Policies $policies
    }
    if ($WhatIfPreference) {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' revoke was evaluated; no changes were applied." -ForegroundColor Yellow
    } else {
        Write-Host "Caller '$($callerServicePrincipal.displayName)' is revoked with a disabled policy tombstone." -ForegroundColor Green
    }
}