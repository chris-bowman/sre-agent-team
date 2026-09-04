# scripts/redeploy-workload-clean.ps1
# Recreates the reference workload side in a deterministic order that avoids
# connector managed-identity token caching without the EscalationCaller role.

[CmdletBinding()]
param (
    [string] $SubscriptionId = '4686fb7a-2bf8-4366-b0ea-7b7c85e63bd7',
    [string] $ResourceGroup = 'workload-rg',
    [string] $Location = 'australiaeast',
    [string] $AgentName = 'WorkloadApp',
    [string] $WorkloadDisplayName = 'Reference Workload SRE Agent',
    [string] $ScopedResourceGroups = 'workload-rg',
    [string] $ProxyEndpointUrl = 'https://sre-escalation-proxy.blackglacier-ad0e7130.australiaeast.azurecontainerapps.io/mcp/',
    [string] $ProxyEntraClientId = '4c4797ca-bf0d-441f-aa2b-dc237e71d7c2'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\common.ps1"

function Write-Step {
    param([string] $Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Grant-AppRoleIfMissing {
    param(
        [Parameter(Mandatory)] [string] $PrincipalId,
        [Parameter(Mandatory)] [string] $PrincipalLabel,
        [Parameter(Mandatory)] [string] $ProxyClientId
    )

    $proxySpObjectId = az ad sp show --id $ProxyClientId --query id -o tsv
    $appRoleId = az ad app show --id $ProxyClientId --query "appRoles[?value=='EscalationCaller'].id | [0]" -o tsv
    if ([string]::IsNullOrWhiteSpace($proxySpObjectId) -or [string]::IsNullOrWhiteSpace($appRoleId)) {
        throw "Could not resolve proxy service principal or EscalationCaller app role for $ProxyClientId."
    }

    $existing = az rest `
        --method GET `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$proxySpObjectId/appRoleAssignedTo" `
        --query "value[?principalId=='$PrincipalId' && appRoleId=='$appRoleId'].id | [0]" `
        -o tsv
    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        Write-Host "  EscalationCaller already assigned to $PrincipalLabel ($PrincipalId)."
        return
    }

    $body = @{
        principalId = $PrincipalId
        resourceId = $proxySpObjectId
        appRoleId = $appRoleId
    } | ConvertTo-Json -Depth 5
    $tmpFile = [System.IO.Path]::GetTempFileName() + '.json'
    [IO.File]::WriteAllText($tmpFile, $body, (New-Object System.Text.UTF8Encoding($false)))
    try {
        az rest `
            --method POST `
            --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$proxySpObjectId/appRoleAssignedTo" `
            --headers 'Content-Type=application/json' `
            --body "@$tmpFile" | Out-Null
        Write-Host "  EscalationCaller assigned to $PrincipalLabel ($PrincipalId)."
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Step 'Set subscription'
az account set --subscription $SubscriptionId

Write-Step 'Delete old workload resource group if present'
if ((az group exists --name $ResourceGroup) -eq 'true') {
    az group delete --name $ResourceGroup --yes --no-wait
    az group wait --name $ResourceGroup --deleted
}

Write-Step 'Create workload resource group and user-assigned identity'
az group create --name $ResourceGroup --location $Location -o table
$identity = az identity create `
    --resource-group $ResourceGroup `
    --name "$AgentName-id" `
    --location $Location `
    -o json | ConvertFrom-Json
Write-Host "UAMI principal: $($identity.principalId)"
Write-Host "UAMI client:    $($identity.clientId)"

Write-Step 'Pre-grant EscalationCaller to workload UAMI'
Grant-AppRoleIfMissing `
    -PrincipalId $identity.principalId `
    -PrincipalLabel "$AgentName-id" `
    -ProxyClientId $ProxyEntraClientId

Write-Step 'Deploy workload agent and connector'
& "$PSScriptRoot\deploy-workload.ps1" `
    -Location $Location `
    -ResourceGroup $ResourceGroup `
    -SubscriptionId $SubscriptionId `
    -AgentName $AgentName `
    -WorkloadDisplayName $WorkloadDisplayName `
    -ScopedResourceGroups $ScopedResourceGroups `
    -EscalationProxyEndpointUrl $ProxyEndpointUrl `
    -EscalationProxyEntraClientId $ProxyEntraClientId

Write-Step 'Complete workload setup and verification'
& "$PSScriptRoot\complete-workload-e2e-setup.ps1" `
    -SubscriptionId $SubscriptionId `
    -ResourceGroup $ResourceGroup `
    -AgentName $AgentName `
    -ProxyEndpointUrl $ProxyEndpointUrl `
    -ProxyEntraClientId $ProxyEntraClientId `
    -WorkloadUamiPrincipalId $identity.principalId
