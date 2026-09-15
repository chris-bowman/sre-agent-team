# Platform Escalation Service — Operator Guide

This directory contains the Python proxy server and Azure Container App infrastructure for the reusable Platform Escalation Service.

## What it does

The service is the **only bridge** between external SRE agents and the privileged Platform SRE Agent.
It allows approved callers to request investigation-only work without holding the `SRE Agent Administrator`
role on the platform agent directly. The workload SRE Agent in this repository is one reference consumer, not a service dependency.

The supported v1 boundary, schemas, authentication profile, error codes, and compatibility routes are defined in
[docs/service-contract-v1.md](../docs/service-contract-v1.md).

Use the canonical trailing-slash MCP endpoint (`https://<proxy-host>/mcp/`) for connector clients; it avoids mount redirects that some clients do not follow.

## Exposed MCP tools (3 only)

| Tool | Description |
|---|---|
| `create_platform_investigation` | Opens a new investigation thread on the platform agent |
| `get_investigation_status` | Polls the status of an investigation |
| `get_investigation_summary` | Retrieves findings once investigation is complete |

## Security

- Callers must present a valid same-tenant, app-only Entra bearer token with the `EscalationCaller` app role.
- Operator-owned caller policy is keyed by the validated caller application ID (`appid`); caller-supplied labels never grant access.
- The proxy's managed identity holds `SRE Agent Administrator` on the **platform SRE agent only**.
- External callers never touch the platform agent directly.
- All calls are logged to Application Insights (via Log Analytics on the Container App Environment).
- Summary responses use a versioned `schema_version` field and redact common credential-shaped values.
- `/health/live` is a dependency-free liveness probe; `/health/ready` returns `503` when platform identity is unavailable.
- The threat model and remaining scale-out decisions are documented in [docs/threat-model.md](../docs/threat-model.md).

## Investigation registry storage

Production deployments use Azure Table Storage through the proxy's user-assigned
managed identity. The infrastructure creates the table-capable storage account,
sets `REGISTRY_BACKEND=table`, and assigns only `Storage Table Data Contributor`
at that account scope. Table deployments require the private VNet, private endpoint,
and private DNS profile; the supported deployment script rejects Table mode without
`-EnablePrivateNetworking`. Local tests and smoke containers use `REGISTRY_BACKEND=memory`
by default.

In the current staging subscription, management-group policy
`MCAPSGovDeployPolicies` applies `StorageAccount_PublicNetwork_Modify` and forces
`publicNetworkAccess=Disabled`. The proxy health endpoints remain available, but
direct Table data-plane validation requires an approved private endpoint/network
path or a policy exception for the test account.

The backend boundary is implemented by `build_investigation_registry()` in
`app/main.py`, so another shared store can replace Azure Tables without changing
the HTTP handlers. The replacement must preserve ownership checks, expiry, quota
counting, and atomic status-poll updates.

## Managing the escalation proxy

### Required operator access

Caller administration requires Azure CLI authentication in the proxy tenant, permissions
to read the Container App and manage app-role assignments on the proxy service principal,
and private network access to the App Configuration endpoint when the private production
profile has public access disabled.
The proxy coordinates are read from `scripts/.deploy-state.json` when available. For a
different machine or environment, pass all four explicitly:

```powershell
$proxy = @{
	EntraAppId     = '<PROXY_ENTRA_CLIENT_ID>'
	SubscriptionId = '<PLATFORM_SUBSCRIPTION_ID>'
	ResourceGroup  = '<PLATFORM_RESOURCE_GROUP>'
	ProxyAppName   = '<PROXY_CONTAINER_APP_NAME>'
}
```

`CallerPrincipalId` is the caller service principal **object ID**, not its application
client ID. Resolve and review the target before making a change:

```powershell
az ad sp show --id '<CALLER_APP_ID_OR_OBJECT_ID>' `
	--query '{displayName:displayName, appId:appId, objectId:id}' -o table

.\scripts\manage-escalation-callers.ps1 -Operation List @proxy |
	Format-Table display_name, appid, principal_id, role_assigned, `
		policy_registered, enabled, maximum_severity, maximum_concurrent_investigations
```

### Caller lifecycle

Onboard a same-tenant caller with an Entra role and an enabled policy:

```powershell
.\scripts\manage-escalation-callers.ps1 -Operation Grant @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>' `
	-CallerDisplayName '<CALLER_NAME>' `
	-MaximumSeverity high `
	-MaximumConcurrentInvestigations 2

.\scripts\manage-escalation-callers.ps1 -Operation Verify @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>'
```

`Verify` emits the caller state and fails unless both authorization layers permit access.
Use `-WhatIf` before either destructive operation:

```powershell
# Reversible suspension: retain the role, disable the policy.
.\scripts\manage-escalation-callers.ps1 -Operation Disable @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>' -WhatIf
.\scripts\manage-escalation-callers.ps1 -Operation Disable @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>'

# Restore a disabled caller. UpdateExistingPolicy is required to change existing state.
.\scripts\manage-escalation-callers.ps1 -Operation Grant @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>' `
	-UpdateExistingPolicy

# Full revocation: remove the role and retain a disabled policy tombstone.
.\scripts\manage-escalation-callers.ps1 -Operation Revoke @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>' -WhatIf
.\scripts\manage-escalation-callers.ps1 -Operation Revoke @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>'
```

Expected states are:

| Lifecycle state | `role_assigned` | `policy_registered` | `enabled` |
|---|---:|---:|---:|
| Granted | `true` | `true` | `true` |
| Disabled | `true` | `true` | `false` |
| Revoked | `false` | `true` | `false` |

The disabled tombstone is intentional. An empty `CALLER_POLICIES_JSON` selects permissive
compatibility mode, in which every caller with the Entra role is accepted. Never delete a
policy entry or clear the policy environment variable to revoke access.

The first managed `Grant`, `Disable`, or `Revoke` bootstraps enabled entries for every
existing `EscalationCaller` assignment before allowlist mode begins. This prevents an
existing approved caller from being locked out. A repeated `Grant` preserves the current
policy and limits unless `-UpdateExistingPolicy` is present; with that switch, only
explicitly supplied limits replace existing values.

The workload helper remains available for SRE Agent deployments:

```powershell
.\scripts\grant-workload-escalation.ps1 -WorkloadName '<WORKLOAD_NAME>'
```

It registers the workload agent's user-assigned and distinct system-assigned identities.
Role-only operation is a compatibility escape hatch and requires explicit
`-SkipPolicyUpdate`; it should not be used for normal production onboarding.

### Validate every mutation

Each policy change creates a Container App revision. Before asking a caller to retry,
confirm inventory, authorization, revision readiness, and both health endpoints:

```powershell
.\scripts\manage-escalation-callers.ps1 -Operation List @proxy |
	Format-Table display_name, role_assigned, policy_registered, enabled

.\scripts\manage-escalation-callers.ps1 -Operation Verify @proxy `
	-CallerPrincipalId '<EXPECTED_AUTHORIZED_CALLER_OBJECT_ID>'

$app = az containerapp show `
	--name $proxy.ProxyAppName `
	--resource-group $proxy.ResourceGroup `
	--subscription $proxy.SubscriptionId -o json | ConvertFrom-Json

$baseUrl = "https://$($app.properties.configuration.ingress.fqdn)"
[pscustomobject]@{
	LatestRevision      = $app.properties.latestRevisionName
	LatestReadyRevision = $app.properties.latestReadyRevisionName
	Liveness            = (Invoke-WebRequest "$baseUrl/health/live" -UseBasicParsing).StatusCode
	Readiness           = (Invoke-WebRequest "$baseUrl/health/ready" -UseBasicParsing).StatusCode
}
```

The latest revision and latest ready revision should match, and both endpoints should
return `200`. Then submit an escalation from the changed caller and one unaffected caller.
A disabled caller should receive a caller-policy error and must not create a platform
investigation thread. A revoked caller may instead fail during token acquisition or role
validation because its Entra assignment has been removed.

### Deployment and policy safety

Run `initialize-escalation-proxy-entra.ps1` once with Microsoft Entra application
administration rights. It creates or reuses the proxy application, configures its
identifier URI and `EscalationCaller` role, ensures the service principal exists, and
stores the stable client ID in deploy state.

Routine `deploy-escalation-proxy.ps1` runs read the currently deployed
`CALLER_POLICIES_JSON` immediately before the Bicep deployment and preserve it. They read
the proxy Entra client ID from deploy state or `-ProxyEntraAppId` and never read or write
the application registration through Microsoft Graph by default. For a first deployment,
`-BootstrapEntraApplication` explicitly opts into running the privileged bootstrap when no
client ID is available.

Do not write raw JSON with `az containerapp update --set-env-vars` from PowerShell on
Windows. Native argument handling can strip the JSON property-name quotes, causing the
new revision to fail at startup. Both supported scripts escape JSON at the Azure CLI
boundary. Use `manage-escalation-callers.ps1` for policy changes and
`deploy-escalation-proxy.ps1 -CallerPoliciesJson` for a controlled full replacement.

If a policy update produces an unhealthy revision, do not remove Entra assignments while
recovering. Restore the last known-good non-empty policy through the management script or
redeploy with `-CallerPoliciesJson '<VALID_POLICY_JSON>'`, wait for readiness, and run the
inventory and two-caller checks above. Clearing the policy is an emergency compatibility
measure only because it authorizes every role-assigned caller.

## Building and deploying the container image

See `scripts/deploy-escalation-proxy.ps1` for full step-by-step instructions.

Quick reference:
```powershell
cd escalation-proxy/app
az acr build --registry <YOUR_REGISTRY> `
	--build-arg PIP_INDEX_URL=https://packagefeedproxy.microsoft.io/pypi/simple/ `
	--image sre-escalation-proxy:latest .
```

The Dockerfile intentionally requires `PIP_INDEX_URL` at build time. This avoids silently downloading Python dependencies from a public package index in environments governed by corporate package-source policy. Use the approved internal HTTPS feed for corporate builds; do not pass credentials in the Dockerfile or commit feed credentials to source control.

## Production Table networking

For a production Table-backed deployment in a tenant that disables public Storage access, enable the private networking profile:

```powershell
.\scripts\deploy-escalation-proxy.ps1 `
	-ResourceGroup platformsre-rg `
	-SubscriptionId <subscription-id> `
	-AcrName <acr-name> `
	-ProxyAppName sre-escalation-proxy-prod `
	-RegistryBackend table `
	-PrivateNetworkName sre-escalation-proxy-prod-vnet `
	-McpEnableDnsRebindingProtection false `
	-EnablePrivateNetworking
```

The profile creates a delegated Container Apps infrastructure subnet, a private-endpoint subnet, `privatelink.table.core.windows.net` and `privatelink.azconfig.io` zones and links, plus private endpoints for the Table registry and Standard-tier App Configuration policy store. Table mode requires this profile; use memory mode only for local or non-production smoke tests. Validate the resulting Container App readiness and a complete create/status/summary lifecycle before scaling beyond one replica.

The `false` protection setting is currently required for this Azure SRE connector test because the MCP SDK rejects the Container Apps host header even when the exact hostname is allowlisted. Treat this as diagnostic-only; restore `-McpEnableDnsRebindingProtection true` after resolving the host-validation compatibility issue.

### Overnight test shutdown

To stop proxy compute without deleting the private networking or Table state, deactivate the active revision:

```powershell
az containerapp revision deactivate `
	--name sre-escalation-proxy-prod `
	--resource-group platformsre-rg `
	--subscription <subscription-id> `
	--revision sre-escalation-proxy-prod--0000009
```

Reactivate it before testing:

```powershell
az containerapp revision activate `
	--name sre-escalation-proxy-prod `
	--resource-group platformsre-rg `
	--subscription <subscription-id> `
	--revision sre-escalation-proxy-prod--0000009
```

Use a new proxy/environment name for the first private deployment. Container Apps VNet integration is an environment-level setting, and the existing memory-backed environment was created without VNet integration; do not mutate the working staging environment in place until a provider-supported migration path is confirmed. Reuse the stable `-ProxyEntraAppId` so existing caller grants remain valid, then update the workload connector to the new `/mcp/` endpoint after validation.
