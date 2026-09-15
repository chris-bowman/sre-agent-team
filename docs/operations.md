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

Production dynamic caller policy uses an App Configuration Standard or Premium store with a `privatelink.azconfig.io` private endpoint and private DNS link in the same VNet. The Free tier does not support private endpoints and is not suitable for the private production profile. Public App Configuration access is disabled in the private profile; the proxy uses bounded SDK timeouts, and the static-policy path is recovery-only.

The private profile also reserves `AzureBastionSubnet` and `operator-management` subnets. They support a temporary private operator runner for policy administration and validation when public App Configuration access is disabled; the runner has no public IP and is not part of the proxy runtime path.

Validate DNS from the running revision whenever network policy changes. Readiness proves Table access; caller-policy and Platform SRE Agent dependencies are reported through structured events and request outcomes.

## Investigation registry metadata

Each investigation record retains the validated caller identifiers, request idempotency data,
the caller-policy values used at admission, and timestamps for creation, activation, terminal
completion, and finalized-findings retrieval. It also records only safe findings metadata:
schema version and validity, summary-selection strategy, and whether redaction occurred.

The registry does not persist report bodies, credentials, bearer tokens, or other investigation
evidence. Existing Table rows created before these metadata fields were introduced remain
readable and use conservative defaults.

Retention is configured independently by data class:

| Data class | Deployment setting | Default | Behavior |
|---|---|---:|---|
| Reserved and active investigation metadata | `ActiveMetadataRetentionDays` | 1 day | Set when the investigation is admitted; bounded cleanup removes expired rows and releases active quota slots. |
| Terminal investigation and finalized findings metadata | `FinalFindingsMetadataRetentionDays` | 7 days | Applied at terminal completion or first findings finalization. Repeated summary reads do not extend retention. Findings content is never stored. |
| Structured audit telemetry | `LogRetentionDays` | 30 days | Enforced by the Log Analytics workspace independently of registry cleanup. |

The proxy runs a bounded registry cleanup sweep immediately when each container replica starts
and every `ExpiryCleanupIntervalSeconds` thereafter (default 300 seconds). Cleanup calls the
configured registry abstraction, so the same lifecycle applies to Table Storage, local memory,
and future backends. `expires_at` does not cause Azure Table Storage to delete an entity by itself.
With multiple replicas, concurrent sweeps are safe: a replica treats an entity already deleted by
another replica as complete and only releases quota after its own successful deletion.

Separately, each replica runs a bounded terminal reconciler every `ReconciliationIntervalSeconds`
(default 60 seconds). It conditionally leases at most `MaxReconciliationsPerSweep` active platform
threads, checks only their terminal status, and atomically marks confirmed `completed` or `failed`
investigations terminal so their caller quota is released even when the caller stops polling. The
lease expires after `ReconciliationLeaseSeconds` (default 55 seconds), allowing another replica to
recover abandoned work without duplicate platform polling. The reconciler never releases uncertain
reservations or returns report bodies; summary validation remains caller-driven.

Changing registry retention affects newly admitted or newly terminal investigations. Existing
rows keep their persisted `expires_at` value. Retention settings must satisfy organizational
privacy, incident-response, and audit requirements before production deployment.

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

Azure App Configuration retains key-value revision history. Caller writes use the loaded ETag, so concurrent updates fail instead of overwriting another operator's change. To roll back, select the previous revision value in App Configuration and write it as the current value with the active label. Confirm a `caller_policy_snapshot_updated` event and run `manage-escalation-callers.ps1 -Operation List` from an operator environment with private connectivity to the App Configuration endpoint. Public workstation access is expected to receive a network-policy `403`.

The `CALLER_POLICIES_JSON` Container App variable remains only as a rollback compatibility path when `APP_CONFIG_ENDPOINT` is absent. Do not use both sources operationally; App Configuration takes precedence. Before using the fallback, capture the current policy through an approved private operator path and restore `APP_CONFIG_ENDPOINT` as soon as the private dependency is repaired.

## Resource-group caller scopes

Azure App Configuration is the production policy authority. Onboard each caller with one or more workload-owned resource groups; names are resolved to canonical IDs and stored in the caller's `allowed_resource_groups` policy field:

```powershell
.\scripts\manage-escalation-callers.ps1 -Operation Grant @proxy `
	-CallerPrincipalId '<CALLER_SERVICE_PRINCIPAL_OBJECT_ID>' `
	-AllowedResourceGroup 'payments-prod'
```

Every new investigation supplies exactly one `resource_group_id` from this operator-owned allowlist. Do not add platform resource groups to caller policies. All verdicts return fixed proxy-authored ownership and handoff guidance; model-generated platform root cause, evidence, resource names, and remediation remain in the platform-owned thread.

This is an admission, routing, and disclosure control. It does not dynamically narrow the Platform SRE Agent's Azure RBAC. Keep that identity restricted to platform-owned scope and normally grant it no workload-resource access. Organizations requiring per-caller platform-tool isolation must use separate platform agents or a trusted tool broker. Treat prompt instructions as defense in depth, not authorization.

Per proxy replica, synchronous Azure SDK work is offloaded with `MaxConcurrentBlockingSdkCalls` (default 16). Platform requests use `MaxConcurrentPlatformRequests` (default 16) and wait up to `PlatformRequestQueueTimeoutSeconds` (default 0.25 seconds) before returning `429`. Tune these with load evidence; multiplying by the maximum replica count gives the approximate service-wide upper bound.

Summary retrieval is limited independently from status polling. `MinSummaryPollIntervalSeconds` defaults to 5 seconds and `MaxSummaryPollsPerInvestigation` defaults to 288; both are persisted in the shared Table record and updated conditionally. `MaxPlatformResponseBytes` defaults to 1 MiB, and only the most recent `MaxAgentMessages` (default 100) are considered during status or findings parsing.

Readiness dependency results are cached and concurrent probes are coalesced per replica for `ReadinessCacheSeconds` (default 5 seconds). This bounds App Configuration, Table, and managed-identity amplification from public probes. A cached failure remains caller-safe and recovers on the first probe after the cache window; liveness never performs dependency checks.

The application readiness deadline defaults to 15 seconds and returns safe `503` on timeout. The Container Apps readiness probe timeout defaults to 20 seconds and must remain greater than the application deadline. This accommodates cold managed-identity and private-endpoint initialization without allowing an unbounded health request or restarting a live process.

### Weekend checkpoint: 2026-09-11

The proxy is intentionally configured with `minReplicas=0`, `maxReplicas=1`, and all revisions are deactivated to guarantee zero weekend replicas. Source checkpoint `c551ca9` and immutable image `sha256:8821370f1b658b85a962acc24f2fe629926661947a0bc293c04631d0798ed3b2` contain the summary controls and readiness deadline; Trivy reported zero HIGH/CRITICAL findings. Do not treat this image as readiness-validated: cold live probes still timed out and caused restart loops.

Resume with a controlled single replica while diagnosing readiness:

```powershell
$revision = az containerapp show `
	--resource-group platformsre-rg `
	--name sre-escalation-proxy `
	--subscription bf3a76f2-1806-416a-8790-136979d3a04b `
	--query properties.latestRevisionName `
	--output tsv

az containerapp revision activate `
	--resource-group platformsre-rg `
	--name sre-escalation-proxy `
	--subscription bf3a76f2-1806-416a-8790-136979d3a04b `
	--revision $revision

az containerapp update `
	--resource-group platformsre-rg `
	--name sre-escalation-proxy `
	--subscription bf3a76f2-1806-416a-8790-136979d3a04b `
	--min-replicas 1 `
	--max-replicas 1
```

Verify `/health/live` first. Then inspect revision-specific console and system logs while invoking `/health/ready` once. Determine which of App Configuration, Table Storage, or managed-identity token acquisition exceeds its bound before restoring two replicas or traffic testing.
