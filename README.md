# Platform Escalation Service for Azure SRE Agents

This repository delivers a reusable Platform Escalation Service for Azure SRE Agents.
It exposes a narrow investigation-only MCP and HTTP boundary to approved same-tenant
application identities while the privileged Platform SRE Agent remains platform-admin owned.

The workload SRE Agent included here is a reference consumer that demonstrates the
escalation flow. It is optional: other agents and services can use the public contracts
without deploying the workload example.

For production, the recommended topology is separate platform and workload subscriptions,
with platform read access assigned at management-group scope. For test or lab scenarios,
you can deploy both agents into a single subscription and keep the separation at the
resource-group and RBAC level instead.

## Service Architecture

```
Approved Caller → [Platform Escalation Service] → Platform SRE Agent
                    (MCP + HTTP,                    (platform scope,
                     3 investigation tools,          admin-only)
                     same-tenant Entra auth)

Reference consumer: Workload SRE Agent → Platform Escalation Service
```

See [docs/service-contract-v1.md](docs/service-contract-v1.md) for supported transports,
schemas, and error behavior. See [docs/architecture.md](docs/architecture.md) for full diagrams
and RBAC tables.

---

## Prerequisites

| Requirement | Details |
|---|---|
| az CLI | >= 2.55 (`az upgrade`) |
| Bicep | >= 0.26 (`az bicep upgrade`) |
| PowerShell | 7+ (`pwsh`). The scripts auto-install the `powershell-yaml` module if missing. |
| Docker / ACR | For building and pushing the escalation proxy container image |
| Python 3.12 | For local testing of the proxy |
| Permissions (platform team) | Contributor on the platform RG, Application Administrator in Entra, and rights to assign RBAC on the chosen platform scope (subscription or management group) |
| Permissions (app team) | Contributor + User Access Administrator on their workload scope |

## Access governance note

This repository is for deployment and wiring of the Platform Escalation Service and its optional reference components:

- Platform SRE Agent resources
- Escalation proxy service
- MCP connector configuration
- Reference workload-agent and custom-agent upload

Treat Azure resource access as an onboarding/governance concern, not as a repository-owned
authorization model. In production, Azure access should be granted through normal SRE Agent
onboarding and approved admin workflows in the portal (or equivalent enterprise process), for example:

This repository is not the source of truth for final Azure resource access grants.

- Platform team access at management group or subscription scope
- Workload team access at workload resource-group scope

Scope and role decisions should be made by an authorized administrator for each environment.

### ACR access behavior

`deploy-escalation-proxy.ps1` now creates the proxy UAMI (if needed) and ensures the `AcrPull` role assignment on the target ACR before deploying the Container App. This makes clean redeploys work even when the proxy identity is recreated.

Required permission: the deploying identity must be able to create role assignments on the target ACR scope (for example, `User Access Administrator` or `Owner` on the ACR or parent scope).

### Register resource providers (each subscription you deploy into)

```powershell
az provider register -n Microsoft.App --wait
```

---

## What is and isn't Infrastructure-as-Code

Azure SRE Agent splits cleanly into two planes, and that shapes how this repo deploys:

| Plane | Configured by | What lives here |
|---|---|---|
| **Infrastructure plane** (ARM/Bicep) | `Microsoft.App/agents@2026-01-01` + `connectors` | The agent resource, its managed identities, knowledge-graph / action config, upgrade channel, **MCP connectors**, and all RBAC. |
| **Data plane** (REST API / portal builder) | `https://<agent-endpoint>/api/v2/...` | **Custom agents (subagents)**, skills, hooks, instructions, display name. There is *no* ARM property for these. |

So the custom agents (`workload-liaison`, `platform-escalation`) **must** be applied after the agent resource exists — either by the scripts (automatic) or by hand (see [Adding custom agents manually](#adding-custom-agents-manually)). This is a product boundary, not a repo limitation.

---

## Deploy everything with one command

`scripts/deploy-all.ps1` runs all four phases in order and passes outputs between
them automatically via a local `scripts/.deploy-state.json` file — no copy/pasting
resource IDs. Components are still fully separable (see [next section](#deploy-components-separately)).

```powershell
# Single-subscription lab
.\scripts\deploy-all.ps1 `
    -PlatformSubscriptionId <sub-id> -PlatformResourceGroup rg-sre-platform `
    -AcrName <your-acr-name> `
    -WorkloadAgentName sre-payments-api -WorkloadDisplayName 'Payments API' `
    -ScopedResourceGroups 'rg-payments-api-prod' `
    -Location australiaeast
```

```powershell
# Separate platform + workload subscriptions, MG-scoped platform RBAC
.\scripts\deploy-all.ps1 `
    -PlatformSubscriptionId <platform-sub> -PlatformResourceGroup rg-sre-platform `
    -PlatformManagementGroupId mg-platform `
    -WorkloadSubscriptionId <workload-sub> -WorkloadResourceGroup rg-sre-payments `
    -AcrName <your-acr-name> `
    -WorkloadAgentName sre-payments-api -WorkloadDisplayName 'Payments API' `
    -ScopedResourceGroups 'rg-payments-api-prod, rg-payments-api-shared' `
    -Location eastus2
```

Re-run a subset (resume) with `-Phases`:

```powershell
.\scripts\deploy-all.ps1 ... -Phases workload,grant      # only the workload phases
.\scripts\deploy-all.ps1 ... -Phases proxy -ResetState   # start a clean state file
```

Add `-SkipCustomAgentUpload` to deploy infrastructure only and add the subagents
by hand later (see [Adding custom agents manually](#adding-custom-agents-manually)).

Full parameter reference is in [Deployment script parameter reference](#deployment-script-parameter-reference).

---

## Deploy components separately

The four phase scripts read prior outputs from the same `scripts/.deploy-state.json`,
so you can run them independently (e.g. platform team vs. app team) without manual
value passing. Run them in this order.

### 1. Platform team: Deploy Platform SRE Agent

```powershell
.\scripts\deploy-platform.ps1 `
    -ResourceGroup rg-sre-platform `
    -SubscriptionId <platform-sub-id> `
    -PlatformManagementGroupId mg-platform `
    -Location eastus2
```

For a single-subscription test deployment, omit `-PlatformManagementGroupId`. Outputs
(`PLATFORM_AGENT_ID`, `PLATFORM_AGENT_ENDPOINT`, `PLATFORM_AGENT_PRINCIPAL`) are saved to
deploy state and uploaded to the agent. The script also uploads
`platform/custom-agents/workload-liaison.yaml`. Use `-SkipCustomAgentUpload` to skip that.

### 2. Platform team: Deploy Escalation Proxy

```powershell
.\scripts\deploy-escalation-proxy.ps1 `
    -ResourceGroup rg-sre-platform `
    -SubscriptionId <platform-sub-id> `
    -AcrName <your-acr-name>
```

`PlatformAgentId` / `PlatformAgentEndpoint` are read from deploy state (pass them
explicitly with `-PlatformAgentId` / `-PlatformAgentEndpoint` if running standalone).
The script resolves the **SRE Agent Administrator** role GUID automatically and passes it
to Bicep. Outputs `PROXY_ENDPOINT_URL` and `PROXY_ENTRA_CLIENT_ID` are saved to state.

### 3. App team: Deploy Workload SRE Agent

```powershell
.\scripts\deploy-workload.ps1 `
    -ResourceGroup rg-sre-<your-team> `
    -SubscriptionId <your-workload-sub-id> `
    -AgentName sre-payments-api `
    -WorkloadDisplayName 'Payments API' `
    -ScopedResourceGroups 'rg-payments-api-prod'
```

`EscalationProxyEndpointUrl` / `EscalationProxyEntraClientId` are read from deploy state
(pass them explicitly when the app team deploys from a different machine). The script
uploads `workload/custom-agents/platform-escalation.yaml`.

### 4. Platform team: Grant escalation access

Run this **once per workload agent onboarded**. This compatibility wrapper grants the Entra role and registers enabled caller policies for the workload's user-assigned and distinct system-assigned identities:

```powershell
.\scripts\grant-workload-escalation.ps1 -WorkloadName payments-api
```

`WorkloadPrincipalId` and `EntraAppId` are read from deploy state, or pass them explicitly:

```powershell
.\scripts\grant-workload-escalation.ps1 `
    -WorkloadPrincipalId <WORKLOAD_AGENT_PRINCIPAL_ID> `
    -EntraAppId <PROXY_ENTRA_CLIENT_ID> `
    -WorkloadName payments-api
```

  For generic callers and lifecycle operations, use `manage-escalation-callers.ps1`:

  ```powershell
  .\scripts\manage-escalation-callers.ps1 -Operation List
  .\scripts\manage-escalation-callers.ps1 -Operation Verify -CallerPrincipalId <OBJECT_ID>
  .\scripts\manage-escalation-callers.ps1 -Operation Disable -CallerPrincipalId <OBJECT_ID> -WhatIf
  .\scripts\manage-escalation-callers.ps1 -Operation Revoke -CallerPrincipalId <OBJECT_ID> -WhatIf
  ```

  `Disable` keeps the Entra assignment and denies the caller through policy. `Revoke` removes the assignment and retains a disabled policy tombstone so an empty allowlist cannot restore permissive behavior. Remove `-WhatIf` only after reviewing the target. A repeated `Grant` preserves an existing policy by default; use `-UpdateExistingPolicy` to re-enable it or change explicitly supplied limits.

---

## Deployment script parameter reference

The tables below document every parameter accepted by the deployment scripts in `scripts/`.

### scripts/deploy-all.ps1

| Parameter | Required | Default | Description |
|---|---|---|---|
| `PlatformSubscriptionId` | Yes | n/a | Subscription used for platform deployment phases (`platform`, `proxy`) and Graph/Entra grant context. |
| `PlatformResourceGroup` | Yes | n/a | Platform resource group for the platform agent and escalation proxy. |
| `PlatformManagementGroupId` | No | `''` | Optional management group ID for platform-scope RBAC decisions in platform deployment. Leave empty for subscription-scope deployments. |
| `PlatformAgentName` | No | `sre-platform` | Name of the platform SRE agent resource. |
| `AcrName` | Yes | n/a | Azure Container Registry name used to build/push the proxy image. |
| `ProxyAppName` | No | `sre-escalation-proxy` | Escalation proxy app/container name prefix. |
| `WorkloadSubscriptionId` | No | `PlatformSubscriptionId` | Subscription for workload phases. If omitted, uses platform subscription (single-subscription/lab pattern). |
| `WorkloadResourceGroup` | No | `rg-sre-<WorkloadAgentName>` | Resource group for workload agent deployment. If omitted, generated from `WorkloadAgentName`. |
| `WorkloadAgentName` | Conditional | `''` | Workload agent name. Required when `workload` or `grant` phase is included. |
| `WorkloadDisplayName` | Conditional | `''` | Friendly display name passed to workload deployment. Required when `workload` or `grant` phase is included. |
| `ScopedResourceGroups` | Conditional | `''` | Comma-separated workload resource groups used for workload scope configuration. Required when `workload` or `grant` phase is included. |
| `Location` | No | `eastus2` | Azure region used for created resource groups/resources unless overridden by parameter files/templates. |
| `EnableApplicationInsights` | No (switch) | Off | Enables Application Insights wiring in platform/workload deployments. |
| `Phases` | No | `platform,proxy,workload,grant` | Ordered subset of phases to run. Allowed values: `platform`, `proxy`, `workload`, `grant`. |
| `ResetState` | No (switch) | Off | Deletes `scripts/.deploy-state.json` before execution. Useful for clean reruns. |
| `SkipCustomAgentUpload` | No (switch) | Off | Skips data-plane custom agent upload in platform/workload phases. |

### scripts/deploy-platform.ps1

| Parameter | Required | Default | Description |
|---|---|---|---|
| `ResourceGroup` | Yes | n/a | Platform resource group. Created if missing. |
| `SubscriptionId` | Yes | n/a | Platform subscription ID. Script sets active subscription to this value. |
| `PlatformManagementGroupId` | No | `''` | Optional management group ID used when assigning platform scope access. Empty means subscription scope. |
| `AgentName` | No | `sre-platform` | Platform agent resource name. |
| `Location` | No | `eastus2` | Region used for resource group creation and deployment parameters. |
| `EnableApplicationInsights` | No (switch) | Off | Enables Application Insights output/deployment path for platform agent. |
| `SkipCustomAgentUpload` | No (switch) | Off | Skips upload of `platform/custom-agents/workload-liaison.yaml`. |
| `SkipCurrentCallerAgentAdminAssignment` | No (switch) | Off | Skips assigning SRE Agent Administrator to the current caller on the deployed platform agent. |

### scripts/deploy-escalation-proxy.ps1

| Parameter | Required | Default | Description |
|---|---|---|---|
| `ResourceGroup` | Yes | n/a | Platform resource group where proxy resources are deployed. |
| `SubscriptionId` | Yes | n/a | Platform subscription used for deployment and ACR/resource lookup. |
| `PlatformAgentId` | No | `''` (resolved from state) | Platform agent ARM resource ID. If not provided, read from deploy state (`PlatformAgentId`). |
| `PlatformAgentEndpoint` | No | `''` (resolved from state) | Platform agent endpoint URL. If not provided, read from deploy state (`PlatformAgentEndpoint`). |
| `AcrName` | Yes | n/a | ACR name used for `az acr build` and container image hosting. |
| `ProxyAppName` | No | `sre-escalation-proxy` | Proxy app name; also influences image and identity naming. |
| `Location` | No | `eastus2` | Deployment region for proxy infrastructure. |
| `ImageTag` | No | UTC timestamp (`yyyyMMddHHmmss`) | Traceability tag used for the ACR build. Deployment resolves and uses the resulting immutable image digest; `latest` is rejected. |
| `CallerPoliciesJson` | No | Existing deployed value, then `''` | Explicit caller policy JSON. When omitted, routine deployment preserves the current Container App value. |

### scripts/deploy-workload.ps1

| Parameter | Required | Default | Description |
|---|---|---|---|
| `ResourceGroup` | Yes | n/a | Workload resource group. Created if missing. |
| `SubscriptionId` | Yes | n/a | Workload subscription ID. Script sets active subscription to this value. |
| `AgentName` | Yes | n/a | Workload SRE agent resource name. |
| `WorkloadDisplayName` | Yes | n/a | Friendly display name parameter passed to workload deployment. |
| `ScopedResourceGroups` | Yes | n/a | Comma-separated workload resource group list used in workload configuration. |
| `EscalationProxyEndpointUrl` | No | `''` (resolved from state) | Escalation proxy endpoint URL. If omitted, resolved from deploy state (`ProxyEndpointUrl`). |
| `EscalationProxyEntraClientId` | No | `''` (resolved from state) | Proxy Entra app client ID. If omitted, resolved from deploy state (`ProxyEntraClientId`). |
| `ParameterFile` | No | `workload/main.bicepparam` | Parameter file path used in workload Bicep deployment. |
| `Location` | No | `eastus2` | Deployment location and RG creation region for workload resources. |
| `EnableApplicationInsights` | No (switch) | Off | Enables Application Insights path for workload agent deployment. |
| `SkipCustomAgentUpload` | No (switch) | Off | Skips upload of workload custom agent YAMLs. |
| `SkipCurrentCallerAgentAdminAssignment` | No (switch) | Off | Skips assigning SRE Agent Administrator to the current caller on workload agent. |

### scripts/grant-workload-escalation.ps1

| Parameter | Required | Default | Description |
|---|---|---|---|
| `WorkloadPrincipalId` | No | `''` (resolved from state) | Workload agent managed identity object ID. If omitted, resolved from state (`WorkloadAgentUamiPrincipal`, then legacy `WorkloadAgentPrincipal`). |
| `EntraAppId` | No | `''` (resolved from state) | Escalation proxy Entra app client ID. If omitted, resolved from state (`ProxyEntraClientId`). |
| `WorkloadName` | No | Caller service-principal display name | Operator-owned policy label for onboarded workload identities. |
| `SubscriptionId` | No | `''` (resolved from state/current CLI context) | Subscription containing the proxy. If omitted, resolved from state (`ProxySubscriptionId`). |
| `ResourceGroup` | No | `''` (resolved from state) | Platform resource group containing the proxy; required to register caller policy. |
| `ProxyAppName` | No | `''` (resolved from state) | Container App name; required to register caller policy. |
| `MaximumSeverity` | No | `critical` | Maximum severity the caller may request. |
| `MaximumConcurrentInvestigations` | No | `10` | Per-caller concurrent investigation quota. |
| `UpdateExistingPolicy` | No (switch) | Off | Re-enables an existing policy and updates only explicitly supplied policy fields. |
| `SkipPolicyUpdate` | No (switch) | Off | Explicit compatibility escape hatch for role-only grants. Without it, missing proxy coordinates fail closed. |

### scripts/manage-escalation-callers.ps1

| Parameter | Required | Default | Description |
|---|---|---|---|
| `Operation` | No | `List` | One of `Grant`, `List`, `Verify`, `Disable`, or `Revoke`. |
| `CallerPrincipalId` | Conditional | `''` (resolved from workload state) | Caller service-principal object ID; required except for `List`. Alias: `WorkloadPrincipalId`. |
| `CallerDisplayName` | No | Service-principal display name | Operator-owned policy label. Alias: `WorkloadName`. |
| `EntraAppId` | No | `''` (resolved from state) | Escalation proxy Entra application client ID. |
| `SubscriptionId` | No | Current Azure CLI subscription | Subscription containing the proxy Container App. |
| `ResourceGroup` | No | `''` (resolved from state) | Platform resource group containing the proxy. |
| `ProxyAppName` | No | `''` (resolved from state) | Proxy Container App name. |
| `MaximumSeverity` | No | `critical` | Policy ceiling used by `Grant`. |
| `MaximumConcurrentInvestigations` | No | `10` | Policy quota used by `Grant`. |
| `UpdateExistingPolicy` | No (switch) | Off | Re-enables an existing policy and updates only explicitly supplied policy fields during `Grant`. |
| `SkipPolicyUpdate` | No (switch) | Off | Compatibility escape hatch that manages only the Entra assignment. |

### Parameter interactions and state behavior

- The scripts share values through `scripts/.deploy-state.json`.
- Passing a parameter explicitly always wins over state-derived values.
- `deploy-all.ps1 -ResetState` deletes the state file before running phases.
- Running standalone scripts on different machines requires explicitly passing values that would otherwise come from state.

---

## Adding custom agents manually

Custom agents are a **data-plane** concept — if you deployed with
`-SkipCustomAgentUpload`, or the automated upload failed, add them by hand.

### Option A — Azure portal (no tooling)

1. Open the SRE Agent in the Azure portal → **Agent builder** → **Subagents** → **Create**.
2. Copy the fields from the YAML file into the form:
   - Platform agent → `platform/custom-agents/workload-liaison.yaml`
   - Workload agent → `workload/custom-agents/platform-escalation.yaml`
3. Map the YAML `spec` fields: `name`, `display_name`, `system_prompt`,
   `handoff_description`, `agent_type`, and (for the workload agent) the `tools` /
   `mcp_tools` lists. Save.

### Option B — REST API (scriptable)

The scripts call this for you, but you can run it directly. The custom-agent name is the
`spec.name` field in the YAML, and the body is the `spec` object as JSON:

```powershell
$endpoint = '<PLATFORM_AGENT_ENDPOINT>'   # e.g. https://sre-platform.abc123.azuresre.ai
$token    = az account get-access-token --resource https://azuresre.dev --query accessToken -o tsv
$name     = 'workload_liaison'
# Build the JSON body from the YAML spec (requires the powershell-yaml module)
Import-Module powershell-yaml
$spec = (ConvertFrom-Yaml (Get-Content platform/custom-agents/workload-liaison.yaml -Raw)).spec
$body = $spec | ConvertTo-Json -Depth 50
Invoke-RestMethod -Method Put `
    -Uri "$($endpoint.TrimEnd('/'))/api/v2/extendedAgent/agents/$name" `
    -Headers @{ Authorization = "Bearer $token" } `
    -ContentType 'application/json' -Body $body
```

You need the **SRE Agent Administrator** role on the agent resource for the data-plane
call to succeed. If you just granted it, allow ~30–60s for RBAC to propagate — the
`Publish-CustomAgentYaml` helper in `scripts/common.ps1` retries on `401/403` for you.

---

## Testing the escalation path

In the workload SRE Agent chat (portal or your MCP client):

```
/agent platform-escalation
Test the escalation path: create a dummy investigation with description "Connectivity test from workload onboarding", severity "low".
```

Expected response: `investigation_id` returned, polling starts, summary returned.

---

## Onboarding additional workload agents

Repeat steps 3–4 for each new app team. Each team:
- Gets their own `Microsoft.App/agents` resource in their own Azure scope, typically a dedicated workload subscription.
- Fills in their own copy of `workload/main.bicepparam`.
- Has their MI granted the `EscalationCaller` app role by the platform team.

For lab environments, those workload agents can also live in the same subscription as the
platform components, provided RBAC and resource-group boundaries are still kept clear.

---

## Repository structure

```
modules/           Reusable Bicep modules
platform/          Platform SRE Agent + custom agents
escalation-proxy/  Python FastMCP proxy + Container App infra
workload/          Workload SRE Agent template + custom agents
scripts/           Deployment PowerShell scripts
docs/              Architecture documentation
```

---

## Known limitations and TODOs

- **Custom agents are data-plane only.** The `Microsoft.App/agents` ARM resource has no
  property for subagents, skills, hooks, or instructions, so they are applied via the
  data-plane API after the agent resource is created (handled by the scripts, or do it by
  hand — see [Adding custom agents manually](#adding-custom-agents-manually)).

- **SRE Agent Administrator role GUID** is now resolved automatically at deploy time
  (`Get-SreAgentAdministratorRoleId` in `scripts/common.ps1`) and passed to the proxy Bicep
  as `sreAgentAdminRoleDefinitionId`. To deploy the proxy Bicep standalone, resolve it with:
  ```powershell
  az role definition list --name "SRE Agent Administrator" --query "[0].name" -o tsv
  ```

- **Custom agent upload** (`Publish-CustomAgentYaml`) now retries on `401/403` (RBAC
  propagation) and `5xx`, ensures the `powershell-yaml` module is present, falls back across
  payload shapes, and surfaces the server error body on failure.

- **MCP connector `Microsoft.App/agents/connectors`** is deployed declaratively in Bicep
  (`modules/mcp-connector-streamable-http.bicep`) using the GA `2026-01-01` API.

- **Proxy token acquisition**: the proxy uses `azure-identity` ManagedIdentityCredential.
  For local testing, set `AZURE_CLIENT_ID` to a service principal and use `DefaultAzureCredential`.
