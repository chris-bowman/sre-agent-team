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

### Structured audit events and derived metrics

Every proxy audit record is one JSON object with `schema_version`, UTC `timestamp`, and `event`. Event-specific dimensions are deliberately limited to safe identifiers and operational values such as `caller_appid`, `investigation_id`, `correlation_id`, `outcome`, `reason`, `severity`, `status_code`, `attempts`, and `duration_ms`. Never add tokens, request evidence, report bodies, platform thread IDs, object secrets, or signed URLs.

| Area | Events | Metric or audit use |
|---|---|---|
| Authorization | `caller_token_validated`, `caller_authorization_denied`, `caller_token_missing_role` | Allowed and denied calls by caller and safe reason |
| Admission and quota | `investigation_reservation_created`, `investigation_admission_denied`, `investigation_reservation_released` | Admission rate, quota denials, and compensated failures |
| Idempotency | `idempotency_replayed`, `idempotency_conflict` | Replay rate and conflicting request detection |
| Lifecycle | `platform_thread_created`, `platform_thread_status_retrieved`, `investigation_terminal` | Created, completed, and failed investigations by caller |
| Platform dependency | `platform_request_completed`, `platform_request_failed`, `platform_circuit_opened`, `platform_circuit_closed` | Request latency, retries, failures, and circuit state |
| Registry and policy | `readiness_check_succeeded`, `readiness_check_failed`, `caller_policy_refresh_failed`, `caller_policy_snapshot_updated` | Dependency availability and policy freshness |
| Findings | `findings_redacted`, `findings_schema_rejected` | Redaction and malformed-report counts without findings content |

Container App console logs can be converted into metrics in Log Analytics. The following pattern parses only the proxy's versioned JSON records; adapt the table name if the Container Apps diagnostic setting targets a workspace-specific table:

```kusto
ContainerAppConsoleLogs_CL
| extend audit = parse_json(Log_s)
| where tostring(audit.schema_version) == "1.0"
| summarize
		count = count(),
		p95_duration_ms = percentile(todouble(audit.duration_ms), 95)
	by event = tostring(audit.event), outcome = tostring(audit.outcome), bin(TimeGenerated, 5m)
```

Authorization and quota audit review can use the same envelope without inspecting request bodies:

```kusto
ContainerAppConsoleLogs_CL
| extend audit = parse_json(Log_s)
| where tostring(audit.event) in ("caller_authorization_denied", "investigation_admission_denied")
| project TimeGenerated, event=tostring(audit.event), caller_appid=tostring(audit.caller_appid), reason=tostring(audit.reason)
```

Deploy the proxy outage rules independently from the application so monitoring changes do not create a Container App revision:

```powershell
.\scripts\deploy-escalation-monitoring.ps1 `
	-ResourceGroup '<PLATFORM_RESOURCE_GROUP>' `
	-SubscriptionId '<PLATFORM_SUBSCRIPTION_ID>' `
	-AlertActionGroupResourceId '<EXISTING_ACTION_GROUP_RESOURCE_ID>'
```

The deployment creates separate five-minute alerts for policy/readiness failures and Platform SRE Agent dependency failures. `AlertActionGroupResourceId` is optional so detection can be deployed before notification routing is approved. An empty value creates visible Azure Monitor alert instances but sends no notifications; production release evidence requires an operator-owned action group with at least one enabled receiver and a successful test notification.

## Caller policy recovery

Azure App Configuration retains key-value revision history. Caller writes use the loaded ETag, so concurrent updates fail instead of overwriting another operator's change. To roll back, select the previous revision value in App Configuration and write it as the current value with the active label. Confirm a `caller_policy_snapshot_updated` event and run `manage-escalation-callers.ps1 -Operation List`.

The `CALLER_POLICIES_JSON` Container App variable remains only as a rollback compatibility path when `APP_CONFIG_ENDPOINT` is absent. Do not use both sources operationally; App Configuration takes precedence.
