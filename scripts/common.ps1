# scripts/common.ps1
# Shared helpers for the SRE Agent Team deployment scripts.
# Dot-source this from each phase script:  . "$PSScriptRoot\common.ps1"
#
# Provides:
#   - Deployment state file helpers (auto-pass values between phases)
#   - Robust custom-agent (subagent) upload to the SRE Agent data plane
#   - Caller identity + SRE Agent Administrator role helpers
#   - Agent endpoint resolution with ARM fallback
#
# These helpers are intentionally side-effect free on import (only function
# definitions and one script-scoped variable), so they are safe to dot-source.

Set-StrictMode -Version Latest

# ── Deployment state file ─────────────────────────────────────────────────────
# A small JSON file under scripts/ that lets each phase publish its outputs and
# later phases (or deploy-all.ps1) read them without manual copy/paste.
# Override the location by setting the SRE_DEPLOY_STATE environment variable.

$script:DefaultDeployStatePath = Join-Path $PSScriptRoot '.deploy-state.json'

function Get-DeployStatePath {
    if ($env:SRE_DEPLOY_STATE) { return $env:SRE_DEPLOY_STATE }
    return $script:DefaultDeployStatePath
}

function Get-DeployState {
    param([string] $Key)

    $path = Get-DeployStatePath
    if (-not (Test-Path -Path $path -PathType Leaf)) {
        return $null
    }

    $raw = Get-Content -Path $path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    $state = $raw | ConvertFrom-Json -AsHashtable
    if (-not $Key) { return $state }

    if ($state.ContainsKey($Key)) {
        return [string]$state[$Key]
    }
    return $null
}

function Set-DeployState {
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Value
    )

    $path = Get-DeployStatePath

    if (Test-Path -Path $path -PathType Leaf) {
        $raw = Get-Content -Path $path -Raw
        $state = if ([string]::IsNullOrWhiteSpace($raw)) { @{} } else { $raw | ConvertFrom-Json -AsHashtable }
    } else {
        $state = @{}
    }

    $state[$Key] = $Value

    $state | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding utf8
}

# Returns the supplied value if non-empty, otherwise the value stored in deploy
# state under $Key. Use to make script parameters optional when chaining phases.
function Resolve-Value {
    param(
        [AllowEmptyString()] [string] $Provided,
        [Parameter(Mandatory)] [string] $StateKey
    )

    if (-not [string]::IsNullOrWhiteSpace($Provided)) { return $Provided }
    return Get-DeployState -Key $StateKey
}

# ── MCP connector materialization ─────────────────────────────────────────────
# Bicep-deployed AzureARM MCP connectors can persist with null extendedProperties
# (type/endpoint/armScope) on first create and stay stuck in 'Connecting'. A
# plain PUT can also leave the broker's cached credential stale after an app-role
# change (observed: role assignment correct, but the connector kept sending a
# role-less token for 9+ minutes until the connector was deleted and recreated).
# Delete-then-create forces a fresh broker session and token acquisition.
# Idempotent — safe to call after every deployment.
function Sync-McpConnectorEnvelope {
    param(
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [Parameter(Mandatory)] [string] $ResourceGroup,
        [Parameter(Mandatory)] [string] $AgentName,
        [Parameter(Mandatory)] [string] $ConnectorName,
        [Parameter(Mandatory)] [string] $EndpointUrl,
        [Parameter(Mandatory)] [string] $ArmScope,
        [string] $ConnectorIdentity = '',
        [string] $ApiVersion = '2026-01-01'
    )

    if ([string]::IsNullOrWhiteSpace($ConnectorIdentity)) {
        # Matches the canonical path form the portal/runtime compares against
        # (see modules/mcp-connector-streamable-http.bicep).
        $ConnectorIdentity = "/subscriptions/$($SubscriptionId.ToLower())/resourcegroups/$($ResourceGroup.ToLower())/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$AgentName-id"
    }

    $connectorUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/agents/$AgentName/connectors/$ConnectorName" + "?api-version=$ApiVersion"
    $agentUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/agents/$AgentName" + "?api-version=$ApiVersion"

    # Ignore not-found — the connector may not exist yet on first deployment.
    az rest --method delete --url $connectorUrl --resource https://management.azure.com/ --output none 2>$null

    # Deleting a connector can temporarily put the parent agent back into
    # InProgress. Wait for it to settle before recreating the child resource.
    $agentReady = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $provisioningState = az rest --method get --url $agentUrl --resource https://management.azure.com/ `
            --query properties.provisioningState --output tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and $provisioningState -eq 'Succeeded') {
            $agentReady = $true
            break
        }
        if ($attempt -lt 30) { Start-Sleep -Seconds 10 }
    }
    if (-not $agentReady) {
        throw "Agent '$AgentName' did not return to provisioning state 'Succeeded' after deleting connector '$ConnectorName'."
    }

    $body = @{
        properties = @{
            dataConnectorType  = 'Mcp'
            dataSource         = $EndpointUrl
            endpoint           = $EndpointUrl
            extendedProperties = @{
                type     = 'http'
                endpoint = $EndpointUrl
                authType = 'AzureARM'
                armScope = $ArmScope
            }
            identity = $ConnectorIdentity
        }
    } | ConvertTo-Json -Depth 10

    # File-based body avoids PowerShell/az.cmd quoting issues with nested JSON.
    $tmpFile = [System.IO.Path]::GetTempFileName() + '.json'
    [IO.File]::WriteAllText($tmpFile, $body, (New-Object System.Text.UTF8Encoding($false)))
    try {
        az rest --method put --url $connectorUrl --resource https://management.azure.com/ `
            --headers 'Content-Type=application/json' --body "@$tmpFile" --output none
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to materialize MCP connector '$ConnectorName' envelope."
        }
    } finally {
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  MCP connector '$ConnectorName' envelope applied." -ForegroundColor Green
}

# Polls the agent data-plane connector status endpoint until Connected/healthy,
# or until MaxAttempts is reached. Non-fatal by design — deployment should not
# fail just because the MCP session negotiation is briefly slow.
function Wait-McpConnectorConnected {
    param(
        [Parameter(Mandatory)] [string] $AgentEndpoint,
        [Parameter(Mandatory)] [string] $ConnectorName,
        [int] $MaxAttempts = 6,
        [int] $DelaySeconds = 5
    )

    $uri = "$($AgentEndpoint.TrimEnd('/'))/api/v2/extendedAgent/connectors/$ConnectorName/status"

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $token = az account get-access-token --resource https://azuresre.dev --query accessToken --output tsv
        try {
            $status = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 30
            if ($status.status -eq 'Connected' -and $status.healthy) {
                Write-Host "  MCP connector '$ConnectorName' is Connected (tools: $($status.details.tools))." -ForegroundColor Green
                return $true
            }
            Write-Host "  Attempt $attempt/${MaxAttempts}: connector status '$($status.status)'. Waiting ${DelaySeconds}s..." -ForegroundColor Yellow
        } catch {
            Write-Host "  Attempt $attempt/${MaxAttempts}: status check failed ($($_.Exception.Message)). Waiting ${DelaySeconds}s..." -ForegroundColor Yellow
        }
        Start-Sleep -Seconds $DelaySeconds
    }

    Write-Warning "MCP connector '$ConnectorName' did not report Connected after $MaxAttempts attempts. Check manually via $uri."
    return $false
}

# ── YAML support ──────────────────────────────────────────────────────────────
# Custom agents (subagents) are authored as YAML. Ensure a YAML parser is
# available; install powershell-yaml on demand if missing.

function Initialize-YamlModule {
    if (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue) { return }

    if (Get-Module -ListAvailable -Name 'powershell-yaml') {
        Import-Module 'powershell-yaml' -ErrorAction Stop
        return
    }

    Write-Host 'powershell-yaml not found — installing for the current user...' -ForegroundColor Yellow
    try {
        Install-Module -Name 'powershell-yaml' -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module 'powershell-yaml' -ErrorAction Stop
    } catch {
        throw @"
Could not load or install the 'powershell-yaml' module, which is required to upload custom agents.
Install it manually, then re-run:

    Install-Module powershell-yaml -Scope CurrentUser

Or skip the upload (-SkipCustomAgentUpload) and add the custom agent in the portal
(see README, 'Adding custom agents manually'). Underlying error: $($_.Exception.Message)
"@
    }
}

# ── HTTP error helpers ────────────────────────────────────────────────────────

function Get-HttpStatusCode {
    param($ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
    } catch { }
    return 0
}

function Get-HttpErrorDetail {
    param($ErrorRecord)

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        return $ErrorRecord.ErrorDetails.Message
    }
    try {
        $stream = $ErrorRecord.Exception.Response.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            return $reader.ReadToEnd()
        }
    } catch { }
    return $ErrorRecord.Exception.Message
}

# ── Custom agent (subagent) upload ────────────────────────────────────────────

function Get-CustomAgentNameFromYaml {
    param([Parameter(Mandatory)] [string] $YamlPath)

    $nameLine = Get-Content -Path $YamlPath |
        Where-Object { $_ -match '^\s*name\s*:\s*' } |
        Select-Object -First 1

    if (-not $nameLine) {
        throw "Could not find a 'name:' field in YAML file: $YamlPath"
    }

    $rawName = ($nameLine -replace '^\s*name\s*:\s*', '').Trim()
    return $rawName.Trim([char[]]@("'", '"'))
}

# Convert a custom-agent YAML file into the JSON payload the data-plane API expects.
function ConvertTo-CustomAgentPayload {
    param(
        [Parameter(Mandatory)] [string] $YamlPath,
        [Parameter(Mandatory)] [string] $CustomAgentName
    )

    Initialize-YamlModule

    $yamlContent  = Get-Content -Path $YamlPath -Raw
    $yamlObject   = ConvertFrom-Yaml -Yaml $yamlContent
    $specObject = if ($null -ne $yamlObject.spec) { $yamlObject.spec } else { $yamlObject }
    $spec = ConvertFrom-Json -InputObject ($specObject | ConvertTo-Json -Depth 50) -AsHashtable

    # Build the dataplane v2 envelope expected by /api/v2/extendedAgent/agents/{name}.
    $name = $CustomAgentName
    if ($spec.ContainsKey('name') -and -not [string]::IsNullOrWhiteSpace([string]$spec.name)) {
        $name = [string]$spec.name
    }

    $instructions = ''
    if ($spec.ContainsKey('system_prompt') -and -not [string]::IsNullOrWhiteSpace([string]$spec.system_prompt)) {
        $instructions = [string]$spec.system_prompt
    } elseif ($spec.ContainsKey('instructions') -and -not [string]::IsNullOrWhiteSpace([string]$spec.instructions)) {
        $instructions = [string]$spec.instructions
    }

    $handoffDescription = ''
    if ($spec.ContainsKey('handoff_description') -and -not [string]::IsNullOrWhiteSpace([string]$spec.handoff_description)) {
        $handoffDescription = [string]$spec.handoff_description
    } elseif ($spec.ContainsKey('handoffDescription') -and -not [string]::IsNullOrWhiteSpace([string]$spec.handoffDescription)) {
        $handoffDescription = [string]$spec.handoffDescription
    }

    $handoffs = @()
    if ($spec.ContainsKey('handoffs') -and $null -ne $spec.handoffs) { $handoffs = @($spec.handoffs) }

    $tools = @()
    if ($spec.ContainsKey('tools') -and $null -ne $spec.tools) { $tools = @($spec.tools) }

    $mcpTools = @()
    if ($spec.ContainsKey('mcp_tools') -and $null -ne $spec.mcp_tools) {
        $mcpTools = @($spec.mcp_tools)
    } elseif ($spec.ContainsKey('mcpTools') -and $null -ne $spec.mcpTools) {
        $mcpTools = @($spec.mcpTools)
    }

    $connectors = $null
    if ($spec.ContainsKey('connectors') -and $null -ne $spec.connectors) {
        $connectors = @($spec.connectors)
    }

    $allowParallelToolCalls = $false
    if ($spec.ContainsKey('allow_parallel_tool_calls') -and $null -ne $spec.allow_parallel_tool_calls) {
        $allowParallelToolCalls = [bool]$spec.allow_parallel_tool_calls
    } elseif ($spec.ContainsKey('allowParallelToolCalls') -and $null -ne $spec.allowParallelToolCalls) {
        $allowParallelToolCalls = [bool]$spec.allowParallelToolCalls
    }

    $enableSkills = $true
    if ($spec.ContainsKey('enable_skills') -and $null -ne $spec.enable_skills) {
        $enableSkills = [bool]$spec.enable_skills
    } elseif ($spec.ContainsKey('enableSkills') -and $null -ne $spec.enableSkills) {
        $enableSkills = [bool]$spec.enableSkills
    }

    return [ordered]@{
        name = $name
        type = 'ExtendedAgent'
        tags = @()
        owner = ''
        properties = [ordered]@{
            instructions = $instructions
            handoffDescription = $handoffDescription
            handoffs = $handoffs
            tools = $tools
            mcpTools = $mcpTools
            connectors = $connectors
            allowParallelToolCalls = $allowParallelToolCalls
            enableSkills = $enableSkills
        }
    }
}

# Upload a single custom agent YAML to the agent data-plane endpoint.
# Retries on auth-propagation (401/403) and transient (5xx) errors with backoff,
# and falls back to alternate payload shapes for older preview builds.
function Publish-CustomAgentYaml {
    param(
        [Parameter(Mandatory)] [string] $AgentEndpoint,
        [Parameter(Mandatory)] [string] $YamlPath,
        [int] $MaxAttempts = 8
    )

    if (-not (Test-Path -Path $YamlPath -PathType Leaf)) {
        throw "Custom agent YAML file not found: $YamlPath"
    }

    $customAgentName = Get-CustomAgentNameFromYaml -YamlPath $YamlPath
    $yamlContent     = Get-Content -Path $YamlPath -Raw
    $payload         = ConvertTo-CustomAgentPayload -YamlPath $YamlPath -CustomAgentName $customAgentName
    $jsonPayload     = $payload | ConvertTo-Json -Depth 50
    $uri             = "$($AgentEndpoint.TrimEnd('/'))/api/v2/extendedAgent/agents/$customAgentName"

    Write-Host "Uploading custom agent '$customAgentName' to $uri" -ForegroundColor Cyan

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $accessToken = az account get-access-token --resource https://azuresre.dev --query accessToken --output tsv
        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            throw 'Failed to acquire access token for the Azure SRE Agent data-plane audience (https://azuresre.dev).'
        }
        $headers = @{ Authorization = "Bearer $accessToken" }

        try {
            Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -ContentType 'application/json' -Body $jsonPayload | Out-Null
            Write-Host "  Uploaded '$customAgentName' (JSON payload)." -ForegroundColor Green
            return
        }
        catch {
            $status = Get-HttpStatusCode -ErrorRecord $_
            $detail = Get-HttpErrorDetail -ErrorRecord $_

            if ($status -eq 415) {
                # Payload-shape mismatch on older preview builds — try YAML then legacy wrapper once.
                try {
                    Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -ContentType 'application/yaml' -Body $yamlContent | Out-Null
                    Write-Host "  Uploaded '$customAgentName' (YAML fallback)." -ForegroundColor Green
                    return
                } catch {
                    try {
                        $legacyBody = @{ yaml = $yamlContent } | ConvertTo-Json -Depth 5
                        Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -ContentType 'application/json' -Body $legacyBody | Out-Null
                        Write-Host "  Uploaded '$customAgentName' (legacy JSON wrapper)." -ForegroundColor Green
                        return
                    } catch {
                        $detail = Get-HttpErrorDetail -ErrorRecord $_
                    }
                }
            }

            $isRetryable = ($status -eq 401 -or $status -eq 403 -or $status -eq 408 -or $status -eq 429 -or $status -ge 500 -or $status -eq 0)
            if ($attempt -lt $MaxAttempts -and $isRetryable) {
                $reason = if ($status -eq 401 -or $status -eq 403) { 'auth not yet propagated' } else { "HTTP $status" }
                $wait   = [Math]::Min(60, 5 * $attempt)
                Write-Host "  Attempt $attempt/$MaxAttempts failed ($reason). Retrying in ${wait}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $wait
                continue
            }

            throw "Custom agent upload failed after $attempt attempt(s). HTTP $status. Detail: $detail"
        }
    }
}

# ── Caller identity + SRE Agent Administrator role ────────────────────────────

function Get-CurrentCallerObjectId {
    $userType = az account show --query user.type --output tsv
    $userName = az account show --query user.name --output tsv

    if ([string]::IsNullOrWhiteSpace($userType) -or [string]::IsNullOrWhiteSpace($userName)) {
        throw 'Could not determine current Azure account identity. Run "az login" first.'
    }

    if ($userType -eq 'user') {
        $userObjectId = az ad signed-in-user show --query id --output tsv
        if ([string]::IsNullOrWhiteSpace($userObjectId)) {
            throw 'Unable to resolve signed-in user object ID from Microsoft Entra.'
        }
        return @{ ObjectId = $userObjectId; PrincipalType = 'User' }
    }

    $spObjectId = az ad sp show --id $userName --query id --output tsv
    if ([string]::IsNullOrWhiteSpace($spObjectId)) {
        throw "Unable to resolve service principal object ID for '$userName'."
    }
    return @{ ObjectId = $spObjectId; PrincipalType = 'ServicePrincipal' }
}

# Resolve the "SRE Agent Administrator" built-in role definition GUID.
function Get-SreAgentAdministratorRoleId {
    $roleId = az role definition list --name 'SRE Agent Administrator' --query '[0].name' --output tsv
    if ([string]::IsNullOrWhiteSpace($roleId)) {
        throw "Could not resolve the 'SRE Agent Administrator' role definition. Confirm the SRE Agent provider is registered and you have read access to role definitions."
    }
    return $roleId
}

function Grant-SreAgentAdministratorOnAgent {
    param([Parameter(Mandatory)] [string] $AgentResourceId)

    $caller   = Get-CurrentCallerObjectId
    $roleId   = Get-SreAgentAdministratorRoleId

    # NOTE: avoid JMESPath functions like length(@) here — on Windows PowerShell
    # strips the quotes and cmd.exe (az.cmd) chokes on the parentheses
    # ("--output was unexpected at this time"). Use a paren-free query and count
    # the returned rows in PowerShell instead.
    $existingIds = az role assignment list `
        --scope $AgentResourceId `
        --assignee-object-id $caller.ObjectId `
        --role $roleId `
        --query '[].id' `
        --output tsv

    if ([string]::IsNullOrWhiteSpace($existingIds)) {
        Write-Host 'Granting SRE Agent Administrator to current caller on the agent resource...' -ForegroundColor Yellow
        az role assignment create `
            --assignee-object-id $caller.ObjectId `
            --assignee-principal-type $caller.PrincipalType `
            --role $roleId `
            --scope $AgentResourceId `
            --description 'Operator access to manage SRE agent custom agents and investigations' | Out-Null
        Write-Host 'SRE Agent Administrator assigned. Allowing time for RBAC propagation...' -ForegroundColor Yellow
        # Publish-CustomAgentYaml also retries on 401/403, this is a head start.
        Start-Sleep -Seconds 15
    } else {
        Write-Host 'Current caller already has SRE Agent Administrator on this agent.'
    }
}

# Idempotent az role assignment create — safe to call on every script run
# (e.g. deploy-platform.ps1 steps 7/8), unlike a bare `az role assignment create`
# which errors when the assignment already exists.
function Grant-RoleAssignmentIfMissing {
    param(
        [Parameter(Mandatory)] [string] $AssigneeObjectId,
        [Parameter(Mandatory)] [string] $RoleDefinitionId,
        [Parameter(Mandatory)] [string] $Scope,
        [string] $Description = '',
        [string] $RoleLabel = $RoleDefinitionId
    )

    $existingIds = az role assignment list `
        --scope $Scope `
        --assignee-object-id $AssigneeObjectId `
        --role $RoleDefinitionId `
        --query '[].id' `
        --output tsv

    if ([string]::IsNullOrWhiteSpace($existingIds)) {
        az role assignment create `
            --assignee-object-id $AssigneeObjectId `
            --role $RoleDefinitionId `
            --scope $Scope `
            --description $Description | Out-Null
        Write-Host "  $RoleLabel assigned on $Scope"
    } else {
        Write-Host "  $RoleLabel already assigned on $Scope"
    }
}

# ── Agent endpoint resolution ─────────────────────────────────────────────────
# The agentEndpoint property is only populated once provisioning completes.
# Poll ARM until it appears (or time out).
function Resolve-AgentEndpoint {
    param(
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [Parameter(Mandatory)] [string] $ResourceGroup,
        [Parameter(Mandatory)] [string] $AgentName,
        [string] $FromDeploymentOutput = '',
        [int] $MaxAttempts = 12
    )

    if (-not [string]::IsNullOrWhiteSpace($FromDeploymentOutput)) {
        return $FromDeploymentOutput
    }

    $armId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/agents/$AgentName"
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $agentJson = az resource show --ids $armId -o json 2>$null
        if ($agentJson) {
            $endpoint = ($agentJson | ConvertFrom-Json).properties.agentEndpoint
            if (-not [string]::IsNullOrWhiteSpace($endpoint)) { return $endpoint }
        }
        if ($attempt -lt $MaxAttempts) {
            Write-Host "  agentEndpoint not ready yet (attempt $attempt/$MaxAttempts) — waiting 10s..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
    }
    throw "Agent '$AgentName' has no agentEndpoint after $MaxAttempts attempts. It may still be provisioning — re-run shortly."
}
