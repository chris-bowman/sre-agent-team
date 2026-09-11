# scripts/test-deployment-prerequisites.ps1
# Read-only preflight checks for a fresh SRE Agent team deployment.

[CmdletBinding()]
param (
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $PlatformResourceGroup,
    [Parameter(Mandatory)] [string] $WorkloadResourceGroup,
    [Parameter(Mandatory)] [string] $AcrName,
    [string] $Location = 'australiaeast',
    [switch] $EnablePrivateNetworking,
    [switch] $BootstrapEntraApplication,
    [switch] $SkipBicepValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param(
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Warning', 'Fail')] [string] $Status,
        [Parameter(Mandatory)] [string] $Check,
        [Parameter(Mandatory)] [string] $Details
    )

    $checks.Add([pscustomobject]@{
        Status  = $Status
        Check   = $Check
        Details = $Details
    })
}

function Test-MinimumVersion {
    param(
        [Parameter(Mandatory)] [string] $Actual,
        [Parameter(Mandatory)] [version] $Minimum
    )

    $parsed = [version]::new()
    return [version]::TryParse($Actual, [ref]$parsed) -and $parsed -ge $Minimum
}

function Invoke-AzJson {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    $output = & az @Arguments --output json 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    if ([string]::IsNullOrWhiteSpace($output)) { return $null }
    return $output | ConvertFrom-Json
}

function Test-ResourceTypeLocation {
    param(
        [Parameter(Mandatory)] [string] $Namespace,
        [Parameter(Mandatory)] [string] $ResourceType,
        [Parameter(Mandatory)] [string] $TargetLocation
    )

    $provider = Invoke-AzJson -Arguments @('provider', 'show', '--namespace', $Namespace)
    if ($null -eq $provider) {
        Add-Check -Status Fail -Check "Region: $Namespace/$ResourceType" -Details 'Provider metadata could not be read.'
        return
    }

    $type = @($provider.resourceTypes | Where-Object resourceType -eq $ResourceType) | Select-Object -First 1
    if ($null -eq $type) {
        Add-Check -Status Fail -Check "Region: $Namespace/$ResourceType" -Details 'Resource type was not found in provider metadata.'
        return
    }

    $locations = @($type.locations | ForEach-Object { $_.Replace(' ', '').ToLowerInvariant() })
    if ($locations.Count -eq 0 -or $locations -contains $TargetLocation.Replace(' ', '').ToLowerInvariant()) {
        Add-Check -Status Pass -Check "Region: $Namespace/$ResourceType" -Details "$TargetLocation is available."
    } else {
        Add-Check -Status Fail -Check "Region: $Namespace/$ResourceType" -Details "$TargetLocation is not listed as available."
    }
}

Write-Host 'Running read-only deployment prerequisite checks...' -ForegroundColor Cyan

if ($null -eq (Get-Command az -ErrorAction SilentlyContinue)) {
    Add-Check -Status Fail -Check 'Azure CLI' -Details 'az was not found on PATH.'
} else {
    $azVersion = (az version --output json | ConvertFrom-Json).'azure-cli'
    if (Test-MinimumVersion -Actual $azVersion -Minimum ([version]'2.55.0')) {
        Add-Check -Status Pass -Check 'Azure CLI' -Details "Version $azVersion."
    } else {
        Add-Check -Status Fail -Check 'Azure CLI' -Details "Version $azVersion; 2.55.0 or later is required."
    }
}

if ($PSVersionTable.PSVersion -ge [version]'7.0.0') {
    Add-Check -Status Pass -Check 'PowerShell' -Details "Version $($PSVersionTable.PSVersion)."
} else {
    Add-Check -Status Fail -Check 'PowerShell' -Details "Version $($PSVersionTable.PSVersion); 7.0 or later is required."
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    Add-Check -Status Warning -Check 'Docker' -Details 'Docker was not found. ACR remote builds do not require it, but local image validation will be unavailable.'
} else {
    Add-Check -Status Pass -Check 'Docker' -Details ((docker --version 2>$null) -join ' ')
}

$account = Invoke-AzJson -Arguments @('account', 'show')
if ($null -eq $account) {
    Add-Check -Status Fail -Check 'Azure authentication' -Details 'No active Azure CLI account. Run Connect-AzAccount or az login.'
} elseif ($account.id -ne $SubscriptionId) {
    Add-Check -Status Fail -Check 'Azure subscription' -Details "Active subscription is $($account.id), expected $SubscriptionId."
} elseif ($account.state -ne 'Enabled') {
    Add-Check -Status Fail -Check 'Azure subscription' -Details "Subscription state is $($account.state)."
} else {
    Add-Check -Status Pass -Check 'Azure subscription' -Details "$($account.name) ($SubscriptionId), tenant $($account.tenantId)."
}

if ($null -ne $account) {
    $signedInUser = Invoke-AzJson -Arguments @('ad', 'signed-in-user', 'show')
    if ($null -eq $signedInUser) {
        Add-Check -Status Fail -Check 'Microsoft Graph' -Details 'Signed-in user could not be resolved.'
    } else {
        Add-Check -Status Pass -Check 'Microsoft Graph' -Details "Signed in as $($signedInUser.userPrincipalName)."

        $scope = "/subscriptions/$SubscriptionId"
        $assignments = Invoke-AzJson -Arguments @(
            'role', 'assignment', 'list',
            '--assignee-object-id', $signedInUser.id,
            '--scope', $scope,
            '--include-inherited'
        )
        $roleNames = @($assignments | ForEach-Object roleDefinitionName | Select-Object -Unique)
        $canDeploy = $roleNames -contains 'Owner' -or $roleNames -contains 'Contributor'
        $canAssignRoles = $roleNames -contains 'Owner' -or $roleNames -contains 'User Access Administrator' -or $roleNames -contains 'Role Based Access Control Administrator'
        if ($canDeploy -and $canAssignRoles) {
            Add-Check -Status Pass -Check 'Subscription RBAC' -Details "Deployment and role-assignment permissions found: $($roleNames -join ', ')."
        } else {
            Add-Check -Status Fail -Check 'Subscription RBAC' -Details "Contributor plus User Access Administrator (or Owner) is required. Found: $($roleNames -join ', ')."
        }

        if ($BootstrapEntraApplication) {
            $graphToken = & az account get-access-token --resource-type ms-graph --query accessToken --output tsv 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($graphToken)) {
                Add-Check -Status Warning -Check 'Entra bootstrap' -Details 'Graph token acquisition passed; directory application-administrator permission cannot be proven without creating an application.'
            } else {
                Add-Check -Status Fail -Check 'Entra bootstrap' -Details 'Microsoft Graph token acquisition failed.'
            }
        }
    }
}

$requiredProviders = @(
    'Microsoft.App',
    'Microsoft.AppConfiguration',
    'Microsoft.ContainerRegistry',
    'Microsoft.Insights',
    'Microsoft.ManagedIdentity',
    'Microsoft.Network',
    'Microsoft.OperationalInsights',
    'Microsoft.Storage'
)
foreach ($namespace in $requiredProviders) {
    $provider = Invoke-AzJson -Arguments @('provider', 'show', '--namespace', $namespace)
    if ($null -ne $provider -and $provider.registrationState -eq 'Registered') {
        Add-Check -Status Pass -Check "Provider: $namespace" -Details 'Registered.'
    } else {
        Add-Check -Status Fail -Check "Provider: $namespace" -Details "Not registered. Run: az provider register --namespace $namespace --wait"
    }
}

if ($EnablePrivateNetworking) {
    $feature = Invoke-AzJson -Arguments @(
        'feature', 'show',
        '--namespace', 'Microsoft.Network',
        '--name', 'AllowBringYourOwnPublicIpAddress',
        '--subscription', $SubscriptionId
    )
    if ($null -ne $feature -and $feature.properties.state -eq 'Registered') {
        Add-Check -Status Pass -Check 'Private networking feature' -Details 'Microsoft.Network/AllowBringYourOwnPublicIpAddress is registered.'
    } else {
        Add-Check -Status Fail -Check 'Private networking feature' -Details 'Register Microsoft.Network/AllowBringYourOwnPublicIpAddress, then re-register Microsoft.Network.'
    }
}

$resourceTypes = @(
    @{ Namespace = 'Microsoft.App'; Type = 'agents' },
    @{ Namespace = 'Microsoft.App'; Type = 'containerApps' },
    @{ Namespace = 'Microsoft.App'; Type = 'managedEnvironments' },
    @{ Namespace = 'Microsoft.AppConfiguration'; Type = 'configurationStores' },
    @{ Namespace = 'Microsoft.ContainerRegistry'; Type = 'registries' },
    @{ Namespace = 'Microsoft.OperationalInsights'; Type = 'workspaces' },
    @{ Namespace = 'Microsoft.Storage'; Type = 'storageAccounts' }
)
foreach ($resourceType in $resourceTypes) {
    Test-ResourceTypeLocation -Namespace $resourceType.Namespace -ResourceType $resourceType.Type -TargetLocation $Location
}

foreach ($resourceGroup in @($PlatformResourceGroup, $WorkloadResourceGroup)) {
    $group = Invoke-AzJson -Arguments @('group', 'show', '--name', $resourceGroup, '--subscription', $SubscriptionId)
    if ($null -eq $group) {
        Add-Check -Status Pass -Check "Resource group: $resourceGroup" -Details "Does not exist and will be created in $Location."
    } elseif ($group.location -eq $Location) {
        Add-Check -Status Pass -Check "Resource group: $resourceGroup" -Details "Exists in $Location."
    } else {
        Add-Check -Status Warning -Check "Resource group: $resourceGroup" -Details "Metadata location is $($group.location), requested location is $Location."
    }
}

$acr = Invoke-AzJson -Arguments @('acr', 'show', '--name', $AcrName, '--subscription', $SubscriptionId)
if ($null -ne $acr) {
    if ($acr.location -ne $Location) {
        Add-Check -Status Fail -Check 'Container registry' -Details "$AcrName exists in $($acr.location), expected $Location."
    } elseif ($acr.resourceGroup -ne $PlatformResourceGroup) {
        Add-Check -Status Warning -Check 'Container registry' -Details "$AcrName exists in resource group $($acr.resourceGroup), not $PlatformResourceGroup."
    } else {
        Add-Check -Status Pass -Check 'Container registry' -Details "$AcrName exists in $PlatformResourceGroup/$Location with SKU $($acr.sku.name)."
    }
} else {
    $availability = Invoke-AzJson -Arguments @('acr', 'check-name', '--name', $AcrName, '--subscription', $SubscriptionId)
    if ($null -ne $availability -and $availability.nameAvailable) {
        Add-Check -Status Pass -Check 'Container registry' -Details "$AcrName is globally available and will be created."
    } else {
        Add-Check -Status Fail -Check 'Container registry' -Details "$AcrName does not exist in this subscription and is not globally available."
    }
}

if (-not $SkipBicepValidation) {
    $bicepVersionOutput = (& az bicep version 2>&1) -join ' '
    $bicepVersionMatch = [regex]::Match($bicepVersionOutput, '(\d+\.\d+\.\d+)')
    if (-not $bicepVersionMatch.Success -or -not (Test-MinimumVersion -Actual $bicepVersionMatch.Value -Minimum ([version]'0.26.0'))) {
        Add-Check -Status Fail -Check 'Bicep CLI' -Details "Version 0.26.0 or later is required. Output: $bicepVersionOutput"
    } else {
        $templates = @(
            "$PSScriptRoot\..\platform\main.bicep",
            "$PSScriptRoot\..\workload\main.bicep",
            "$PSScriptRoot\..\escalation-proxy\infrastructure\main.bicep",
            "$PSScriptRoot\..\escalation-proxy\infrastructure\monitoring.bicep"
        )
        $failedTemplates = @()
        foreach ($template in $templates) {
            & az bicep build --file $template --stdout 1>$null 2>$null
            if ($LASTEXITCODE -ne 0) { $failedTemplates += $template }
        }
        if ($failedTemplates.Count -eq 0) {
            Add-Check -Status Pass -Check 'Bicep templates' -Details "All $($templates.Count) entry-point templates compiled with Bicep $($bicepVersionMatch.Value)."
        } else {
            Add-Check -Status Fail -Check 'Bicep templates' -Details "Compilation failed: $($failedTemplates -join ', ')."
        }
    }
}

Write-Host ''
$checks | Format-Table -AutoSize -Wrap
$failed = @($checks | Where-Object Status -eq 'Fail')
$warnings = @($checks | Where-Object Status -eq 'Warning')
Write-Host "`nSummary: $($checks.Count - $failed.Count - $warnings.Count) passed, $($warnings.Count) warnings, $($failed.Count) failed."

if ($failed.Count -gt 0) {
    throw 'Deployment prerequisite checks failed.'
}

Write-Host 'Deployment prerequisites passed.' -ForegroundColor Green
