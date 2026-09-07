# Production Operations

## Required DNS and egress

The proxy requires outbound HTTPS (`TCP/443`) and successful DNS resolution for:

| Destination | Purpose |
|---|---|
| The configured `*.azuresre.ai` Platform SRE Agent endpoint | Create and read investigation threads |
| `login.microsoftonline.com` | Microsoft Entra token acquisition |
| `*.azconfig.io` | Dynamic caller-policy reads |
| Azure Monitor and Log Analytics ingestion endpoints for the deployment region | Container logs and telemetry |
| The configured `*.table.core.windows.net` endpoint | Investigation registry access |

Production Table Storage uses the `privatelink.table.core.windows.net` private zone linked to the Container Apps VNet. The storage account's public network access and shared-key access remain disabled. The Container Apps subnet uses the managed NAT gateway for public egress. Restrictive firewalls must allow the service tags or documented FQDNs required by Entra, Azure Monitor, App Configuration, and the Platform SRE Agent endpoint.

Validate DNS from the running revision whenever network policy changes. Readiness proves Table access; caller-policy and Platform SRE Agent dependencies are reported through structured events and request outcomes.

## Monitoring and alerts

Collect Container App console and system logs in the deployment's Log Analytics workspace. Alert on:

| Signal | Suggested condition | Operator action |
|---|---|---|
| Readiness failures | Any sustained `/health/ready` failure for 5 minutes | Check Table DNS, private endpoint, RBAC, and storage health |
| Caller policy refresh failures | Any `caller_policy_refresh_failed` event; urgent when `using_last_known_good=false` | Check App Configuration availability, DNS, and Data Reader assignment |
| Circuit open | Any `platform_circuit_opened` event | Check Platform SRE Agent health and outbound connectivity |
| Dependency 5xx | Elevated `503` responses for 5 minutes | Separate registry, policy, and platform dependency events before remediation |
| Authorization denials | Unexpected increase by caller app ID | Verify app-role assignments and active policy revision |
| Quota denials | Sustained `429` responses | Check abandoned investigations and caller quota sizing |
| Replica health | Ready replicas below configured minimum | Inspect revision and Container Apps system logs |

Do not place bearer tokens, credentials, signed URLs, platform thread IDs, or unredacted findings in alerts. Use correlation ID, caller app ID, operation, status, and safe error category for diagnosis.

## Caller policy recovery

Azure App Configuration retains key-value revision history. Caller writes use the loaded ETag, so concurrent updates fail instead of overwriting another operator's change. To roll back, select the previous revision value in App Configuration and write it as the current value with the active label. Confirm a `caller_policy_snapshot_updated` event and run `manage-escalation-callers.ps1 -Operation List`.

The `CALLER_POLICIES_JSON` Container App variable remains only as a rollback compatibility path when `APP_CONFIG_ENDPOINT` is absent. Do not use both sources operationally; App Configuration takes precedence.
