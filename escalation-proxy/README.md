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
at that account scope. Local tests use `REGISTRY_BACKEND=memory` by default.

In the current staging subscription, management-group policy
`MCAPSGovDeployPolicies` applies `StorageAccount_PublicNetwork_Modify` and forces
`publicNetworkAccess=Disabled`. The proxy health endpoints remain available, but
direct Table data-plane validation requires an approved private endpoint/network
path or a policy exception for the test account.

The backend boundary is implemented by `build_investigation_registry()` in
`app/main.py`, so another shared store can replace Azure Tables without changing
the HTTP handlers. The replacement must preserve ownership checks, expiry, quota
counting, and atomic status-poll updates.

## Onboarding a new caller

When a new same-tenant application caller is approved, the platform team grants its service principal the `EscalationCaller` app role:

```powershell
\.\scripts\grant-workload-escalation.ps1 -WorkloadPrincipalId "<caller-service-principal-object-id>" -EntraAppId "<proxy-entra-app-client-id>"
```

The existing script name and parameter are retained for compatibility; the target principal can be any approved caller service principal.

The proxy Entra application is bootstrapped once and reused on later deployments. Pass its stable client ID to routine deployments with `-ProxyEntraAppId`.

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

The profile creates a delegated Container Apps infrastructure subnet, a private-endpoint subnet, the `privatelink.table.core.windows.net` zone and link, and a Table private endpoint. The default remains opt-in so memory-backed staging deployments do not create networking resources. Validate the resulting Container App readiness and a complete create/status/summary lifecycle before scaling beyond one replica.

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
