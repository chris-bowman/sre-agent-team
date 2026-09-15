# Open Platform Escalation Service Implementation Plan

## Status

- Overall: v1.0.0 released; the 2026-09-11 assessment reopened security and reliability acceptance. Broader production rollout is not recommended until the post-assessment gate passes.
- Current work package: local remediation candidate; readiness timeout/cancellation and Table SDK conflict handling are repaired and smoke-tested, while authorized private-Table staging and WP13 sign-off remain open
- Last updated: 2026-09-11
- Primary product: Platform SRE Agent and least-privilege escalation proxy
- Reference consumer: Workload SRE Agent
- Normative v1 contract: [service-contract-v1.md](service-contract-v1.md)

## Session checkpoint and continuation plan

**Checkpoint date: 2026-09-11**

The 2026-09-11 read-only assessment is the current handoff. Earlier deployment checkpoints below are historical evidence, not proof that the newly identified security cases pass. WP9-WP13 and the post-assessment gate supersede conflicting completion claims.

### Security assessment handoff (2026-09-11)

- Reviewed release commit `9e52e29577b2564056f76601e2df4a9f881ef7d3`. All 94 existing tests passed, but additional local probes exposed authorization, output-boundary, query-isolation, and concurrency defects.
- SDK-backed/local simulations reproduced wildcard Table ETags, quota-one admitting two reservations, expired-policy acceptance after a failed refresh, disabled-caller reads, unvalidated intermediate summaries, unsafe OData predicates, and repeated POST attempts after an uncertain creation outcome.
- Readiness returned `200` with platform calls configured to fail; dependency `503` responses reported `internal_error` with `retryable: false`.
- Validation was source review and local mocked testing, not a production penetration test. No application code, cloud resources, or release artifacts were changed by the assessment.
- The image scan previously recorded 51 HIGH and 3 CRITICAL OS-package findings without fixes. These are scanner findings requiring exploitability triage, not proof of remotely exploitable application vulnerabilities; a fixable-only gate is not blanket acceptance.
- Start with WP9. WP10 and WP11 address the other high-priority defects; WP12 handles availability and deployment controls; WP13 owns independent verification and renewed sign-off. See the finding-to-work-item map below.
- On 2026-09-14, candidate commit `f155ff3` was deployed to private-Table staging as immutable image digest `sha256:392e2f21cc43b3d0c041c55affb4d5f809d96eb7a5ad3802d80c6871110cd65a`. The WorkloadApp reference connector completed investigation `c3c6c7dd-e6e2-4da0-a6ee-3b6b0919aa9b`; the proxy recorded platform completion and terminal completion at 2026-09-14 01:01:20 UTC, with healthy liveness/readiness and no proxy failure events. This is positive reference-connector evidence, not a substitute for the broader P13.3 fault and isolation matrix.
- On 2026-09-14, a separate `WorkloadIsolation` agent was provisioned in `workload-isolation-rg`, scoped only to that resource group, granted an enabled `EscalationCaller` policy with a high-severity ceiling and quota two, and its three-tool connector was recovered to `Connected` after connector recreation. The proxy is now latest-ready with two healthy replicas on the same candidate digest; this prepares, but does not by itself complete, the two-caller P13.3 lifecycle and fault matrix.
- On 2026-09-15, diagnosis confirmed the proxy's App Configuration store was Free-tier with no private endpoint, while the production proxy runs in a private VNet. The service recovered through the documented static-policy fallback, but the durable fix is now encoded in Bicep: Standard App Configuration, `privatelink.azconfig.io` private DNS, a private endpoint in the existing private-endpoint subnet, and public App Configuration access disabled for the private Table profile. Deployment of this SKU/network change remains an operator-approved step because it changes Azure cost and networking.
- On 2026-09-15, the App Configuration private-link remediation was deployed and the static fallback removed. Standard-tier App Configuration has public access disabled and an approved private endpoint; the two-replica proxy loaded `caller_policy_snapshot_updated` from its private endpoint and retained readiness. The WorkloadApp reference E2E investigation `40ec098b-c194-4ddf-a6b6-9b9f6ceb49be` then completed: the proxy selected the liaison's strict Markdown report (`best_structured_message`), accepted `ESCALATION_FINAL_V1`, recorded `findings_schema_valid: true`, and returned the caller-safe completed JSON result. Candidate revision `sre-escalation-proxy--0000024` uses digest `sha256:901e6c50d63159f65c4bf552d62856d75d9c8c1ff96ddfeb27338ae2dacb41a1` with two healthy replicas.
- On 2026-09-15, two concurrently admitted callers completed independent schema-valid investigations: WorkloadApp `d974277f-830c-4c9a-9d36-af03907df001` and WorkloadIsolation `35bfca6a-5166-4519-9f5d-fce34e330260`. Reciprocal foreign-ID lookups returned opaque `404` responses. An in-flight WorkloadApp investigation `005c2397-4227-4011-ae14-c9fd4e895ea0` also survived a supported rolling restart: both original replicas drained, two replacements (`...-7wp4l`, `...-zb58p`) became ready, and the same investigation returned a schema-valid finalized summary at 01:57:51 UTC. No Table, quota, readiness, or platform-request failure events were observed.
- On 2026-09-15, WorkloadApp created investigation `6217b2dc-fa19-4693-bb08-306be5aed605` using idempotency key `p13-replay-20250915`. An identical retry returned the same ID and the proxy recorded `idempotency_replayed`; a retry that changed only the description returned `409 Idempotency key was used with a different request`, with no new investigation. Proxy liveness, readiness, and MCP health remained `200` throughout.

### Runtime recovery and release hardening (2026-09-07)

- Azure activity logs established the September 4 outage root cause: the sole proxy revision was explicitly deactivated and both SRE Agent runtimes were explicitly stopped. ARM `provisioningState=Succeeded` was not sufficient evidence that an agent runtime was running.
- Restored both SRE Agent runtimes and the proxy without replacing stable identities. The current proxy revision is `sre-escalation-proxy--logfix090702`, running two ready replicas on immutable image `acrsrelabjplayn.azurecr.io/sre-escalation-proxy@sha256:7f7f94545c53d8442c00c891748d1f8e19efc9d62f47c9ab6a57f46f99bd3b3f`.
- All four public health checks return `200`: `/health/live`, `/health/ready`, `/health`, and `/mcp/health`. Readiness now covers caller-policy, registry, and Platform SRE Agent dependencies.
- Deployment now refuses to proceed when the existing latest-ready revision is inactive, uses unique immutable image tags resolved to ACR digests, and waits with a bounded retry loop for App Configuration data-plane RBAC propagation before ARM deployment.
- Caller policy authority moved to Azure App Configuration key `escalation/caller-policies` with label `production`. Routine deployment seeds only when the key is absent, preserving operator-managed policy. Quoted ETag conditional writes and terminating REST failures prevent false-success policy updates. Five production caller policies remain registered.
- App Configuration refresh uses a bounded cache and valid last-known-good snapshot. Startup fails closed without an initial policy, and readiness fails when no current or acceptable last-known-good policy exists.
- Platform dependency calls now use explicit timeouts, bounded retries with jitter, a circuit breaker, and safe `503` responses. Registry and Platform SRE Agent dependency failures were exercised against readiness and recovery behavior; alert rules are deployed, while notification routing and delivered-alert evidence remain open under P8.9.
- Sensitive-log review found that `platform_thread_created` included the platform thread ID. The field was removed, a regression test was added, and the logging-fix image above was deployed. Recent current-revision logs contain no bearer/authorization material, SAS-like values, report bodies, or `platform_thread_id` on the audited lifecycle events.
- The supported deployment script built the immutable image but was blocked before ARM deployment by Microsoft Graph CAE error `TokenCreatedWithOutdatedPolicies`. The already-built digest was deployed through the Bicep-owned path with existing stable Entra values; a fresh interactive sign-in is still required before the Graph-dependent full script can run normally.
- After proxy deployment, WorkloadApp's connector regressed to `Connecting` and custom-agent definitions returned `404`. Delete/recreate connector synchronization, custom-agent republish, and bounded status polling restored `platform-escalation-mi` to `Connected`, healthy, with all three tools.
- Local validation is green: Ruff format and lint, mypy, compileall, 69 pytest tests, 9 PowerShell parses, 6 Bicep builds, 3 Bicep parameter builds, and `git diff --check` all pass.
- An SRE-Agent-originated smoke selected `workload-escalation-parent`, delegated to `platform-escalation`, created exactly one synthetic read-only investigation, polled it to completion, retrieved the summary, and returned a structured final report. Both delegated task groups completed without failure, the agent reported eight tool calls over approximately 232 seconds, no Azure resources were modified, all health checks remained green, and no proxy errors or sensitive log markers were observed.

### Overnight restoration and functional validation (2026-09-04)

- Restored the Bicep-owned NAT gateway, static public IP, and Storage Table private endpoint without replacing the SRE agents, resetting deployment state, or changing the stable proxy Entra client ID `4c4797ca-bf0d-441f-aa2b-dc237e71d7c2`.
- Proxy image `acrsrelabjplayn.azurecr.io/sre-escalation-proxy:p510-20260904-02` resolved and deployed as `acrsrelabjplayn.azurecr.io/sre-escalation-proxy@sha256:b22a4561f47751f5126634c0ee889f490e3981a03b74e468966bfb8ca25bc064`. The Python base image and complete runtime dependency graph are also digest/version pinned. The revision is healthy with two ready replicas; liveness and readiness return `200`.
- The immutable redeployment preserved proxy Entra client ID `4c4797ca-bf0d-441f-aa2b-dc237e71d7c2`, app role ID `f0d9990a-554c-4556-a743-4e16d842dfe9`, five existing caller grants, and both healthy three-tool connectors. Deployment state now records `ProxyImageDigest` and `ProxyImageReference`.
- The escalation service runtime is Azure Container Apps. The separate shared demo cluster `aks-srelab` is not part of this service path and remains intentionally stopped for cost control.
- Storage public access remains disabled. The Table private endpoint is approved, private DNS is linked, and the restored NAT/public-IP egress path is provisioned.
- Refreshed `platform-escalation-mi` on both WorkloadApp and WorkloadIsolation after the proxy restoration. Both connectors are `Connected`, healthy, expose three tools, and report zero consecutive ping failures.
- Fresh simultaneous caller smoke passed. WorkloadApp investigation `8eee83d2-1e05-4e57-93d3-13e8887c6091` and WorkloadIsolation investigation `d48e05ab-2d0e-4ca1-97f5-247ced55009c` both completed. Proxy audit events recorded `summary_status=completed`, `summary_selection=best_structured_message`, HTTP `200`, and required finalization token `ESCALATION_FINAL_V1` for both investigations.
- The workload-facing final reports intentionally omit the consumed finalization token; proxy audit events and MCP results are the authoritative completion evidence.
- No matching Table, ETag, quota, storage, `ERROR`, or `Traceback` events were observed in the restored revision logs.
- Validation remains green: 58 proxy tests, 8 PowerShell parses, and 6 Bicep builds.
- Repository cleanup removed regenerable ARM JSON and transient test/build artifacts, archived the completed Phase 0 security summary and presentation script under `docs/archive`, and updated ignore rules. Bicep source remains authoritative for generated ARM templates. Git is initialized on branch `main` with initial commit `4b72b57`.
- Official MCP SDK conformance coverage now validates initialization, initialized notifications, ping heartbeats, exact three-tool discovery, all supported calls, malformed requests, unknown methods and tools, authorization failures, and reconnects through fresh client sessions.

### Fresh deployment validation (2026-09-01)

- Recreated `platformsre-rg` and `workload-rg` in `australiaeast` after both groups were cleaned.
- Platform agent: `https://sre-platform--6514b06f.ba56c019.australiaeast.azuresre.ai`.
- Private Table-backed proxy: `https://sre-escalation-proxy.happyisland-89fe2a77.australiaeast.azurecontainerapps.io/mcp/`.
- Workload agent: `https://workloadapp--317fd7c5.81d8f7bf.australiaeast.azuresre.ai`.
- Proxy revision `sre-escalation-proxy--0000006` is healthy with `minReplicas=2`, `maxReplicas=2`; both replicas are ready and liveness and readiness probes return `200`.
- Storage public access is disabled; the Table private endpoint is approved and the private DNS/VNet link is active.
- Both workload identities have `EscalationCaller`; `platform-escalation-mi` is `Connected`, healthy, and exposes all three tools.
- Workload smoke test investigation `86f59f3b-952b-47f8-b0d9-8763d38a2578` completed end to end through the private Table-backed proxy. The proxy created platform thread `bfb2b8f1-b7d3-42dc-97d7-3db12d61c7e1`, observed the lifecycle transition from `running` to `completed`, and returned a structured summary with `FINALIZATION_TOKEN: ESCALATION_FINAL_V1`.
- Two-replica investigation `879e0efe-58b2-441e-9397-f395ca542b82` validated shared Table state across replicas: reservation and thread creation were handled by replica `...-gq7g6`, status polling was served by both replicas, and summary retrieval returned `ESCALATION_FINAL_V1`. No Table, ETag, quota, or application errors were observed. Restart survival remains pending because the investigation completed before a targeted restart could be proven.
- Restart-survival investigation `9d03c7fd-0629-4829-826e-49a6771ca9a0` remained `running` across a supported rolling revision restart at `01:07:53Z`. Both original replicas were replaced, polling continued on both replacements, status reached `completed` at `01:12:00Z`, and summary retrieval returned `ESCALATION_FINAL_V1` at `01:12:12Z`. No matching Table, ETag, storage, quota, or application errors were observed.
- Quota-one validation exposed a terminal lifecycle defect: completed investigations remained `active`, so persisted quota counters were not decremented. Terminal completion now atomically marks the Table row terminal and releases its slot; status-first and finalized-summary-first paths are idempotent. Admission also reconciles a rejecting counter from authoritative unexpired `reserved` and `active` rows.
- Repair image `acrsrelabjplayn.azurecr.io/sre-escalation-proxy:quota-release-20260901-01` has digest `sha256:f6768a8cf4199e91f687d8ac039a80cfc6a2895801c07b223287c90b219d290c`. Current image `acrsrelabjplayn.azurecr.io/sre-escalation-proxy:quota-reconcile-20260901-01` has digest `sha256:5ec83102ae99f1ac0f80dfb0d4744cb43c7edfe4fb563cbc434c5a289a74bfe8`.
- Under a temporary WorkloadApp quota of one, investigation `ee397bee-e8c2-487c-a6d4-ca79287ba9c0` was admitted while an overlapping request was rejected with `429`. The admitted investigation reached `completed` and returned `ESCALATION_FINAL_V1`.
- Post-completion investigation `22e412bd-7eb3-4338-bbbb-e5b818f1d074` was admitted, proving the terminal slot was reusable. Reservation and creation ran on one replica, polling crossed both replicas, completion was observed on the other replica, and the finalized summary returned `ESCALATION_FINAL_V1`. No matching lifecycle failures were observed.
- The temporary `CALLER_POLICIES_JSON` override was removed. Revision `sre-escalation-proxy--0000006` is latest and latest-ready, `Healthy`, and `RunningAtMaxScale` with two ready replicas; Table mode and the repaired image are unchanged. The WorkloadApp connector is `Connected`, healthy, exposes three tools, and reports zero consecutive ping failures.
- Validation passed: 58 proxy tests, 8 PowerShell parses, and 6 Bicep builds.

### ✅ Recently Completed (2026-08-31)

- **Production Table-backed proxy deployment succeeded**: Private networking, storage account, Container App, and health probes all operational.
  - Container App: `sre-escalation-proxy` at `https://sre-escalation-proxy.blackglacier-ad0e7130.australiaeast.azurecontainerapps.io`
  - Storage: `sreocoxujof5ynqsregistry` with private endpoint, private DNS, and isolated VNet
  - Health: `/health/live` (200), `/health/ready` (200) — confirms Table backend initialized and accessible
  - Logs: Clean startup, liveness probes every 25–30s, no initialization errors
- **Private networking fully configured**: VNet (10.42.0.0/16), Container Apps subnet (10.42.0.0/27), Storage PE subnet (10.42.1.0/28), NAT Gateway, private DNS zone
- **Production deployment path validated**: Bicep, Azure RBAC, private endpoint provisioning, and Storage SDK initialization all working under policy-restricted storage account

### Release gate status

**Historical v1 evidence only:** the completion statements below describe the earlier tests. Authorization, idempotency, quota concurrency, findings/log safety, outage semantics, and vulnerability acceptance are reopened under WP9-WP13. Successful connector operation and delivered alerts do not establish these security properties.

- **Caller administration and negative authorization**: Complete; independent-caller isolation, reciprocal cross-caller denial, simultaneous lifecycle, same-caller quota, terminal release, cross-replica access, restart survival, disabled/revoked callers, live idempotency, and severity-limit enforcement are validated.
- **Official MCP conformance**: Complete; official-client tests cover negotiation, reconnect behavior, malformed requests, authorization failures, and all supported tool paths.
- **Outage behavior**: Complete; readiness, retries, safe public errors, and recovery were validated for registry and Platform SRE Agent failures. Two severity-1 scheduled-query alert rules route to the operator-owned `AGOwner` action group, and Azure Monitor plus recipient inbox confirmation prove email delivery.
- **Immutable image/release controls**: Complete; deployment resolves the pushed tag to a validated ACR digest, the base image is digest-pinned, and all runtime packages are exact-pinned.
- **Repository governance files and CI/security checks**: MIT license, contribution guide, security policy, code of conduct, changelog, operations guidance, CI checks, and image scanning are implemented.

### Post-v1 operational priorities

1. **Remediate assessment findings**: Implement WP9-WP12 and pass WP13 before recommending broader production rollout. This plan does not authorize deployment or production fault injection.
2. **Operate the existing release**: Monitor outage alerts, connector health, investigation retention, and caller-policy refresh telemetry; healthy probes do not override the open findings.
3. **Authentication maintenance**: Refresh the interactive Azure CLI sign-in before the next Graph-dependent deployment run.

### Working assumptions for future work

- The platform service remains the primary product; the workload SRE Agent remains a reference consumer example.
- Azure Table Storage is actively deployed, but prior sequential and lifecycle tests did not prove adversarial concurrent admission or injected-key isolation. WP10 reopens those guarantees while retaining the earlier restart and lifecycle evidence.
- Future work starts from the tagged v1 contract and preserves backward compatibility for supported callers.

## Objective

Reposition this repository around the Platform SRE Agent and its escalation proxy as a reusable platform service. The proxy provides a narrow, secured investigation path for external agents without granting them direct administrative access to the Platform SRE Agent.

The first supported caller boundary is same-tenant Microsoft Entra application identities. Standards-compliant MCP Streamable HTTP and a versioned asynchronous HTTP API are both supported public contracts backed by the same authorization and investigation service layer.

## Execution Strategy

The original roadmap consists of eight work packages, followed by five post-assessment packages:

1. WP1-WP3 establish the public contract and portable transports.
2. WP4-WP6 harden state, deployment, and the findings boundary.
3. WP7 repositions the repository and adds generic examples.
4. WP8 provides the release gate.
5. WP9-WP11 remediate authorization, persistence/idempotency, and output/trust-boundary findings.
6. WP12 hardens availability and deployment controls; WP13 revalidates the release, including image-risk disposition.

Do not start production networking or repository-wide terminology changes before the shared contract and transport architecture are merged.

## Scope Decisions

- Same-tenant service identities are the v1 caller boundary.
- Delegated-user tokens, anonymous callers, and cross-tenant callers are excluded from v1.
- Standards-compliant MCP Streamable HTTP and versioned asynchronous HTTP are both supported contracts.
- The proxy remains investigation-only: create, follow status, and retrieve findings.
- Remediation, mutation, broad SRE Agent administration, and direct platform-agent access are excluded.
- Azure Table Storage remains the initial production registry, but only with working private networking and atomic concurrency semantics.
- The workload SRE Agent remains a reference consumer, not a required platform component.
- Existing MCP tool names and HTTP routes receive a compatibility window while v1 contracts are introduced.

## Review Findings

The findings immediately below are the original pre-v1 review, retained for traceability. The current open assessment is recorded under **2026-09-11 Assessment: Remediation Backlog** after WP8.

### Release Blockers

1. `/mcp` is currently a hand-built JSON-RPC subset tailored to the Azure SRE Agent connector rather than a standards-compliant Streamable HTTP transport.
2. `scripts/deploy-escalation-proxy.ps1` creates a new Entra application registration on every deployment, changing the token audience and invalidating existing onboarding.
3. The Table registry has no private network path, while the memory fallback permits multiple replicas and loses state on restart.
4. Authorization is only an app-role grant plus caller-supplied `workload_name`; no operator-owned caller policy exists.

### High-Priority Hardening

1. MCP validates a token and then decodes it again without signature verification for dispatch.
2. Table quota enforcement is check-then-create rather than atomic, and creation has no idempotency key.
3. Registry expiry cleanup only runs at process startup and scans the table.
4. Health endpoints do not verify registry or Platform SRE Agent dependencies.
5. Only the summary response is versioned; lifecycle responses and errors are not stable public contracts.
6. Findings are selected heuristically from free-form output and scrubbed with regular expressions.
7. Runtime dependencies are open-ended minimum versions, test dependencies ship in the image, and deployments use mutable image tags.

### Repository Positioning Gaps

1. Top-level documentation presents a two-tier workload/platform solution rather than a platform service plus reference consumer.
2. Consumer onboarding is named and implemented only for workload SRE agents.
3. The platform liaison contains fixed ALZ assumptions that are not universal service behavior.
4. The repository has no license, contribution guide, security policy, code of conduct, changelog policy, or CI workflow.
5. Existing documentation contains stale validation, implementation, telemetry, and polling statements.

## WP1: Define the Supported Service Contract

**Goal:** Establish the product boundary and one versioned contract before runtime refactoring.

- [x] P1.1 Document the v1 product boundary and support matrix.
- [x] P1.2 Define shared request, lifecycle, findings, and problem-detail schemas.
- [x] P1.3 Define stable schemas and error semantics for the three existing MCP tools.
- [x] P1.4 Define `/api/v1` HTTP routes and one-release compatibility behavior for current routes.
- [x] P1.5 Define an operator-owned caller registration model keyed by validated Entra `appid`.

### WP1 Acceptance Criteria

- The Platform SRE Agent remains explicitly privileged and admin-only.
- Caller-provided workload or team labels are documented as untrusted display metadata, never authorization identity.
- Contracts include schema version, investigation ID, lifecycle status, timestamps, expiry, correlation ID, polling guidance, findings, and standard errors.
- Caller policy includes enabled state, display name, severity ceiling, concurrent quota, and audit metadata.
- Existing tool names remain `create_platform_investigation`, `get_investigation_status`, and `get_investigation_summary`.

## WP2: Isolate Domain Logic and Replace the MCP Transport

**Goal:** Make MCP portable while preventing authorization drift between transports.

- [x] P2.1 Extract configuration and shared domain models from `escalation-proxy/app/main.py`.
- [x] P2.2 Extract token validation and caller-policy enforcement. `authorization.py` now owns JWKS signature verification, tenant and audience checks, app-only identity and role enforcement, authorization-header handling, severity-claim limits, and policy-backend construction. HTTP and MCP retain one configured authorization instance and existing compatibility aliases.
- [x] P2.3 Extract investigation lifecycle, registry, Platform SRE Agent client, output validation, and audit events. `investigation_service.py`, `investigation_registry.py`, `platform_client.py`, `output_validation.py`, and `telemetry.py` now own those concerns; `main.py` retains thin late-bound compatibility adapters shared by HTTP and MCP. The full suite passes with 92 tests, and Ruff format/lint, mypy, Bandit, compileall, and editor diagnostics are clean.
- [x] P2.4 Route MCP and HTTP through the same existing domain implementation methods.
- [x] P2.5 Replace the hand-written MCP dispatcher with the pinned official Python MCP SDK Streamable HTTP transport.
- [x] P2.6 Carry the verified caller identity through dispatch without unverified token decoding.
- [x] P2.7 Add official-client MCP conformance tests and Azure SRE connector regression coverage.

### WP2 Acceptance Criteria

- MCP supports protocol negotiation, notifications, content negotiation, reconnect behavior, and standards-compatible errors.
- Only the three escalation tools are exposed.
- Signature, tenant, issuer, audience, app-only token shape, role, application ID, and object ID are validated once and reused.
- Tests cover initialize, tools/list, all tools/call paths, malformed requests, invalid authorization, unknown methods, and unknown tools.

## WP3: Stabilize the Asynchronous HTTP API

**Goal:** Provide a framework-neutral integration contract alongside MCP.

- [x] P3.1 Implement versioned HTTP endpoints over the shared domain service.
- [x] P3.2 Return typed creation, status, findings, and problem-detail responses.
- [x] P3.3 Add `Retry-After` or `poll_after_seconds` guidance.
- [x] P3.4 Add caller-scoped idempotency keys to investigation creation.
- [x] P3.5 Retain current routes as deprecated compatibility wrappers for one release.
- [x] P3.6 Publish generated OpenAPI and a same-tenant consumer guide.

### WP3 Acceptance Criteria

- Duplicate creation retries return the original investigation.
- Public errors contain no internal exception text.
- HTTP examples cover managed identity and client credentials without tenant-specific IDs or secrets.
- Versioning and deprecation behavior are documented.

## WP4: Make Persistence and Scaling Safe

**Goal:** Preserve ownership, quotas, and investigation state under concurrency, restart, and scale-out.

- [x] P4.1 Extend registry records with idempotency, caller-policy snapshot, lifecycle timestamps, and structured-findings metadata. Both memory and Table backends now retain the policy values used at admission, activation/completion/finalization timestamps, and safe findings schema, selection, and redaction metadata without persisting report content. Older Table rows deserialize with conservative defaults.
- [x] P4.2 Make quota check and creation atomic using conditional writes, transactions, or a per-caller counter record.
- [x] P4.3 Add bounded continuous expiry cleanup without full-table startup scans. Each proxy replica now runs an immediate and periodic backend-neutral cleanup worker, with a configurable interval, bounded batches, transient-failure recovery, clean shutdown, and idempotent Table deletion under replica races.
- [x] P4.4 Define separate retention settings for active metadata, final findings, and audit telemetry. Active registry metadata defaults to 1 day, terminal and finalized-findings metadata defaults to 7 days without storing findings content, and Log Analytics audit telemetry remains independently configurable at 30 days. Repeated summary reads do not extend registry retention.
- [x] P4.5 Restrict memory mode to local development and one replica.
- [x] P4.6 Add separate liveness and dependency-aware readiness endpoints.
- [x] P4.7 Configure Container Apps probes for the new health model.
- [x] **P4.8 (2026-08-31) Deploy production Table infrastructure with private networking and validate single-replica initialization.**

### WP4 Acceptance Criteria

- ✅ Single-replica Table initialization and health checks validated
- ✅ Table mode preserves shared investigation state across multiple replicas and a rolling revision restart.
- ✅ Memory mode is visibly non-production and cannot scale beyond one replica.
- ✅ Readiness checks registry access and a bounded platform authentication/connectivity operation.
- ✅ Concurrent callers cannot exceed their configured quota, while independent caller partitions admit overlapping work.

## WP5: Secure and Repeatably Deploy the Platform Service

**Goal:** Preserve the service identity and operate safely in policy-restricted Azure environments.

- [x] P5.1 Split Entra application bootstrap from routine proxy deployment. The idempotent `initialize-escalation-proxy-entra.ps1` owns application, identifier URI, app-role, and service-principal setup; routine deployment consumes a validated existing client ID without Microsoft Graph access unless the operator explicitly supplies `-BootstrapEntraApplication` for first-run setup.
- [x] P5.2 Make deployment reuse a stable proxy application client ID when supplied or uniquely discoverable.
- [x] P5.3 Add idempotent grant, list, verify, disable, and revoke operations for same-tenant callers. The operator command synchronizes Entra app-role assignments with caller policy, bootstraps existing grants before enabling allowlist mode, supports `-WhatIf`, and preserves policy across redeployment.
- [x] P5.4 Retain workload-oriented parameter aliases during the compatibility window. `manage-escalation-callers.ps1` preserves `WorkloadPrincipalId` and `WorkloadName` aliases for the caller-oriented parameters.
- [x] **P5.5 Add a production profile with VNet-integrated Container Apps, Storage private endpoint, and private DNS. (2026-08-31)**
- [x] **P5.6 Disable Storage public network access in production mode. (2026-08-31 — enforced by tenant policy)**
- [x] P5.7 Document required Entra and Platform SRE Agent egress/DNS paths. `docs/operations.md` records the required HTTPS destinations, private Table DNS, and production egress expectations.
- [x] P5.8 Parameterize limits, retention, replicas, log retention, ingress profile, probes, finalization policy, and tags. ✅ Replica bounds and Log Analytics retention are parameterized
- [x] P5.9 Create registry storage and RBAC only when the selected backend requires them.
- [x] P5.10 Deploy immutable image tags or digests and pin runtime dependencies.
- [x] P5.11 Separate runtime dependencies from development and test dependencies.
- [x] P5.12 Add bounded retry with jitter, explicit timeouts, circuit-breaking behavior, and dependency-specific status mapping. ✅ Bounded retry, jitter, explicit timeouts, and safe 503 mapping are complete
- [x] P5.13 Move caller policy from `CALLER_POLICIES_JSON` to Azure App Configuration. Production uses the labeled `escalation/caller-policies` snapshot through managed identity and least-privilege data-plane RBAC over private networking. Refresh validation, bounded propagation, last-known-good caching, fail-closed startup, maximum staleness, disabled tombstones, ETag administration, independent `EscalationCaller` enforcement, revision history, migration, rollback compatibility, and live grant/disable/revoke/severity/quota changes have been tested without creating Container App revisions. `CALLER_POLICIES_JSON` remains only as the documented rollback source when `APP_CONFIG_ENDPOINT` is absent.

### WP5 Implementation Progress (2026-08-31)

- ✅ Production Bicep infrastructure: VNet, subnets, NAT Gateway, private endpoint, private DNS zone, Container App environment, Storage account, RBAC assignment
- ✅ Deployment reuse: Script preserves Entra app ID when supplied via `-ProxyEntraAppId`; multiple deployments use same client ID
- ✅ Privilege separation: Entra application bootstrap is a separate idempotent command; routine proxy deployment uses deploy state or an explicit client ID and contains no Graph operations.
- ✅ Policy-compliant networking: tenant policy forces `publicNetworkAccess=Disabled` on storage; private endpoint + VNet integration bypasses this
- ✅ Runtime dependencies split: production image uses `requirements.txt`; test dependencies in `requirements-dev.txt`
- ✅ Parameterized Container App: minReplicas, maxReplicas, logRetentionDays configurable; revisionSuffix forced for immutable redeploy
- ✅ Immutable image deployment: the release tag is resolved to a validated ACR `sha256` digest before Bicep deployment; the Python base image and complete runtime package graph are pinned.

### WP5 Acceptance Criteria

- ✅ A routine redeployment preserves the Entra audience and all caller grants.
- ✅ Production Table traffic uses private networking under restrictive storage policy.
- ✅ The container runs non-root and uses an immutable, reproducible dependency set.
- ⏳ Platform dependency failures are distinguishable from caller errors and terminal investigation failures (pending multi-replica test)
- Caller-scoped idempotency keys and request fingerprints are persisted in both registry implementations; matching retries replay the existing investigation and conflicting payloads are rejected.
- Both registry backends now reserve a caller slot before Platform SRE thread creation, finalize it after success, and release it on failure. The memory backend protects admission with a lock, while the Table backend uses a per-caller transaction counter.
- The Table backend now uses a per-caller quota counter and same-partition transaction to atomically increment the counter while creating a reservation. Live private-Storage concurrency validation remains a release-gate test.
- `CALLER_POLICIES_JSON` supports operator-owned same-tenant caller registration by validated app ID, including enabled state, severity ceiling, and concurrent quota. Empty configuration preserves local development behavior; `manage-escalation-callers.ps1` persists policy changes on the Container App and routine deployment preserves the current value.
- The v1 HTTP lifecycle routes are implemented and tested for create, status, findings, bounded polling, canonical response envelopes, and incomplete findings handling.
- Versioned HTTP failures now return stable `application/problem+json` responses with safe error codes, correlation IDs, and retryability; legacy and MCP error behavior remain unchanged.
- Checkpoint verification: 38 tests passed, Bicep compilation passed, PowerShell deployment-script parsing passed, and editor diagnostics are clean.
- Corporate package-source policy is confirmed by the build environment: public PyPI access fails from the image, while the approved corporate HTTPS feed succeeds. The Dockerfile now requires an explicit `PIP_INDEX_URL` build argument and does not embed credentials.
- `deploy-escalation-proxy.ps1` passes `PIP_INDEX_URL` to ACR builds, with an overridable approved-feed default, so routine deployments match the validated container build path.
- Deployment now resolves the emitted Container Apps FQDN and configures it in `MCP_ALLOWED_HOSTS`, preserving MCP DNS-rebinding protection in hosted environments.
- Connector deployments use the canonical `/mcp/` endpoint to avoid HTTP redirect handling differences in Azure SRE connector clients.
- Post-host-allowlist deployable-artifact smoke passed: the image rebuilt from the corporate feed, ran as non-root `appuser`, and returned 200 from `/health/live` and `/mcp`; the temporary container was removed after log inspection.
- Memory-backed deployments now conditionally omit the registry Storage account and Storage Table role assignment; generated Bicep confirms both resources are gated on `registryBackend=table`.
- Runtime and test dependencies are split into `requirements.txt` and `requirements-dev.txt`; the production image rebuilds successfully without pytest. On 2026-09-04, the validated production runtime graph was exact-pinned, the Python base image was digest-pinned, and ACR digest deployment completed successfully.
- All Platform SRE Agent HTTP calls now use bounded exponential retry with jitter, configured timeouts, and safe 503 mapping after transient failures; circuit-breaking remains open.
- Container App minimum/maximum replica bounds and Log Analytics retention are now deployment parameters; memory mode remains forcibly single-replica.
- Container validation completed with the corporate feed: image build succeeded, image runs as non-root `appuser`, `/health/live` returned 200, `/mcp` returned 200, startup logs were clean, and the validation container was removed.
- The previous Docker validation note is superseded; remaining container work is vulnerability scanning and immutable release tagging.
- Focused local deployment smoke completed using `REGISTRY_BACKEND=memory`: a fresh image build passed, `/health/live` returned 200, `/health/ready` returned expected 503 without managed identity, `/mcp` probe succeeded, OpenAPI exposed the v1 routes, and invalid MCP authorization returned 403 rather than a server failure.
- Readiness now verifies both the active registry backend and managed-identity token acquisition; either dependency failure returns a safe 503 response without internal details.
- The v1 findings endpoint now parses only finalized liaison reports with required Root Cause, Evidence, Recommended Actions, and Verdict sections. Malformed finalized reports are rejected with a safe 502 response instead of being converted into placeholder findings.
- Findings redaction now covers credential-shaped assignments, multiline JSON secret values, and signed URL query parameters before public return.
- Each investigation now uses one correlation ID in the registry and Platform SRE request context; caller responses expose only the opaque investigation ID and correlation ID, never the platform thread ID.
- Added `.github/workflows/proxy-validation.yml`; configure the repository or organization `PIP_INDEX_URL` variable with the approved corporate HTTPS package feed before enabling CI runs.
- All six repository Bicep sources compile successfully; only the available Bicep CLI update warning was emitted.
- All six repository PowerShell scripts parse successfully with the PowerShell AST parser.
- Fresh memory-backed staging deployment completed in `platformsre-rg` and `workload-rg`: the platform agent, proxy, workload reference agent, and both `EscalationCaller` grants deployed successfully. The proxy is healthy at its canonical `/mcp/` endpoint.
- The workload connector initially followed a `/mcp` redirect; republishing `/mcp/` and resyncing the connector produced direct MCP `200` traffic. Remaining connector `403`s are a verified managed-identity token cache issue: Graph shows the workload UAMI has `EscalationCaller`, but received tokens still contain `roles: []`.
- Restarting the fresh workload agent refreshed the connector session: `platform-escalation-mi` now reports `Connected`, healthy, with all three tools. Direct MCP traffic reaches `/mcp/` successfully.
- 2026-08-27 controlled staging lifecycle completed through the WorkloadApp reference consumer: create returned investigation `de4fc309-d72d-4821-a7b6-ca37ba653c50`, inline long-polling reached the platform thread, and the investigation completed successfully. This proves the deployed Azure SRE connector and the three-tool lifecycle for one caller; two-caller isolation, final report evidence capture, and Table-backed production validation remain open.
- 2026-08-27 added an opt-in production networking profile to the proxy Bicep and deployment script: delegated Container Apps infrastructure subnet, private-endpoint subnet, Table private endpoint, and `privatelink.table.core.windows.net` private DNS zone/link. The template and script compile/parse successfully; live private-network validation remains open.
- 2026-08-27 ARM what-if confirmed the existing memory-backed Container Apps environment has no VNet configuration and proposed broad environment-property deletions when VNet integration was added. Treat the private Table rollout as a parallel proxy/environment deployment with a new name, followed by lifecycle validation and connector cutover; do not mutate the working staging environment in place.
- 2026-08-27 private test topology selected: an isolated VNet named `sre-escalation-proxy-prod-vnet` in `platformsre-rg`, using `10.42.0.0/16`, a delegated `10.42.0.0/27` Container Apps subnet, and a `10.42.1.0/28` Storage private-endpoint subnet. These are explicit deployment parameters.
- 2026-08-27 clean private Table deployment succeeded after adding a NAT Gateway for Container Apps egress. The proxy runs as `sre-escalation-proxy-prod` with Table storage, an approved private endpoint, readiness `200`, and image digest `sha256:3f21c0887d8d6041dab3c03d7479923af1c609048d550fd3a6885f811a0a3fa8` (initial deployment) / latest diagnostic revision rebuilt from the same source.
- 2026-08-27 WorkloadApp connector cutover succeeded: `platform-escalation-mi` reports `Connected` with 3 tools against the new `/mcp/` endpoint, and the proxy logs show the expected UAMI with `roles: ["EscalationCaller"]`. Connector negotiation currently requires diagnostic `MCP_ENABLE_DNS_REBINDING_PROTECTION=false` because the SDK rejects the Azure Container Apps Host header despite exact allowlist entries; restore protection and resolve this compatibility issue before release.
- 2026-08-27 Table ETag failure remediation: status polling previously read a Table entity, reread it through ownership validation, then updated using the first read's stale ETag. Polling now validates and updates from one entity read, while reservation finalize/release use conditional ETag retries. Focused security and contract tests pass (50); corrected private proxy revision deployed with image digest `sha256:ec6b61c914e252e2c96b54d0d733ba8973b3c9835008e1358d4f57d0b0f8da4d`.
- 2026-08-27 follow-up runtime failure: Table expiry cleanup treated the per-caller `__quota_counter__` entity as an investigation and accessed missing `caller_appid`, causing the observed KeyError. Cleanup now skips counter rows and guards caller identity access. Regression suite passes (51 tests); private Table proxy redeployed and readiness is `200`. The reported caller client ID `7723791a-2e73-401b-ba39-3403d9f680ce` does not exist in this subscription; current WorkloadApp UAMI is client `1cedc4c0-4c8c-4fa2-9530-376651a6e521`, principal `fc86570c-452a-4eed-a5c4-59dabd498bb0`, with `EscalationCaller` verified.
- 2026-08-27 repeated ETag failure was not identity-cache related: connector status was `Connected`, tokens contained the expected `appid` and `EscalationCaller`, and the proxy was running with `maxReplicas=5`. Added Table ETag normalization (`etag`/`_etag`), conditional retry backoff for quota and reservation updates, and conflict telemetry. Focused suite remains green (51 tests). Deployed revision `sre-escalation-proxy-prod--0000007` with Table backend and temporary `minReplicas=1`, `maxReplicas=1` for controlled retry testing.
- 2026-08-27 investigation `864b614f-63cd-4ee7-b1d8-f588a72ff16d` completed successfully through the private Table-backed proxy: reservation and platform thread creation succeeded, status polling reached `completed`, and summary retrieval returned `summary_status=completed` with `finalization_token=ESCALATION_FINAL_V1`. This validates the repaired single-replica production path; two-caller and multi-replica concurrency validation remain open.
- 2026-08-27 scale-out gate started: `sre-escalation-proxy-prod` is pinned to two running replicas on revision `sre-escalation-proxy-prod--0000008`; repeated readiness probes returned `200`, the WorkloadApp connector remains `Connected`, and both replicas started cleanly. Concurrent two-caller lifecycle and restart-survival evidence remain open.
- 2026-08-27 overnight cost reduction: removed orphaned `sre-escalation-proxy-id` and `sre-escalation-proxy-v2-id` identities, their old `SRE Agent Administrator`/`AcrPull` assignments, and old `sre-escalation-proxy-logs`/`sre-escalation-proxy-v2-logs` workspaces. Scaled the active proxy to `minReplicas=0,maxReplicas=1`, then deactivated revision `sre-escalation-proxy-prod--0000009`; its replica is `NotRunning`. Retained the production Table, private endpoint, isolated VNet, NAT, and DNS resources for tomorrow's testing.
- 2026-08-27 two-investigation concurrency validation passed on the two-replica Table deployment: investigations `9eac9704-b206-4f42-8cf8-d36fa8dbee9a` and `d49d598d-6c30-4698-9934-8d784243cb56` each produced a reservation, platform thread, 54 status observations in aggregate, and a completed structured summary with `ESCALATION_FINAL_V1`. No Table conflict telemetry was emitted for either run.
- 2026-09-01 fresh two-replica shared-state validation passed for investigation `879e0efe-58b2-441e-9397-f395ca542b82`: replica `...-gq7g6` created the reservation and platform thread, both replicas served status polls, and `...-gq7g6` returned the completed structured summary with `ESCALATION_FINAL_V1`. No Table, ETag, quota, or application errors were emitted. This validates multi-replica access but not restart survival; the investigation completed before a targeted replica recycle could be proven.
- 2026-09-01 rolling restart-survival validation passed for investigation `9d03c7fd-0629-4829-826e-49a6771ca9a0`: the revision restart was accepted at `01:07:53Z` while status was `running`; both original replicas were replaced by `...-8r87t` and `...-bknzg`; polls continued throughout replacement; completion was observed at `01:12:00Z`; and summary retrieval returned `ESCALATION_FINAL_V1` at `01:12:12Z`. No matching Table, ETag, storage, quota, or application errors were emitted.
- 2026-09-01 quota-one validation exposed persisted terminal-slot leakage: completed investigations retained `reservation_state=active`, so the per-caller counter remained saturated. Terminal status and finalized-summary paths now call idempotent completion, and Table completion atomically decrements the counter while marking the investigation terminal. Admission reconciles a rejecting counter from authoritative unexpired active rows. Four focused regressions and the full 58-test proxy suite pass.
- 2026-09-01 repaired deployment used image `quota-release-20260901-01` (`sha256:f6768a8cf4199e91f687d8ac039a80cfc6a2895801c07b223287c90b219d290c`) followed by current image `quota-reconcile-20260901-01` (`sha256:5ec83102ae99f1ac0f80dfb0d4744cb43c7edfe4fb563cbc434c5a289a74bfe8`). All three known pre-fix active investigations were replayed through the repaired terminal lifecycle before retesting.
- 2026-09-01 same-caller quota-one gate passed: investigation `ee397bee-e8c2-487c-a6d4-ca79287ba9c0` was admitted, an overlapping request received `429`, and the admitted lifecycle completed with `ESCALATION_FINAL_V1`. This validates rejection for one caller but does not prove independent-caller isolation.
- 2026-09-01 post-completion slot-reuse and restored-policy smoke passed with investigation `22e412bd-7eb3-4338-bbbb-e5b818f1d074`. It was admitted after the quota-one investigation completed, crossed both replicas, reached `completed`, and returned `ESCALATION_FINAL_V1`. The temporary caller policy was removed; revision `sre-escalation-proxy--0000006` is latest/latest-ready and healthy at 2/2, health endpoints return `200`, and `platform-escalation-mi` is connected and healthy with three tools and zero consecutive ping failures.
- 2026-09-01 independent-caller release gate passed after recreating only `WorkloadIsolation` at `https://workloadisolation--f4d74d8c.81d8f7bf.australiaeast.azuresre.ai` with its pre-authorized UAMI attached before first connector negotiation. Proxy logs validated client `680b181a-79d8-4cf5-b2b6-48c324e9781e`, principal `00aea911-b2ec-4adf-a8fc-a12799b267f5`, with `roles: ["EscalationCaller"]`; the connector was `Connected`, healthy, with three tools.
- 2026-09-01 overlapping independent callers were both admitted on separate proxy replicas: WorkloadIsolation client `680b181a-79d8-4cf5-b2b6-48c324e9781e` created investigation `bf751933-3029-479b-b8ae-df1ff13bad90` at `06:14:32Z`, and WorkloadApp client `4a0f25fe-4dbd-48f8-aa3e-aee25f71ff2d` created investigation `4b6748fc-fd43-4663-ada3-38398fd7a557` at `06:14:35Z`. Reciprocal status lookups returned opaque `not found` MCP errors (`isError: true`) and disclosed no foreign state. Both owned lifecycles completed and returned `ESCALATION_FINAL_V1` at `06:19:40Z` and `06:18:44Z`, respectively; no matching Table, ETag, quota, storage, or application errors were emitted.
- 2026-09-01 connector recovery exposed a deployment-helper race: connector deletion can temporarily return the parent agent to `InProgress`. `Sync-McpConnectorEnvelope` now waits up to five minutes for parent provisioning state `Succeeded` before recreating the connector child. Temporary isolation connector references in the local custom-agent YAML files were restored to canonical `platform-escalation-mi`; WorkloadApp and `.deploy-state.json` were not changed.
- 2026-09-01 overnight cost shutdown completed after the release gates: `sre-escalation-proxy` was reduced to `minReplicas=0,maxReplicas=1`, revision `sre-escalation-proxy--0000006` was deactivated, and Azure reported `Stopped` with zero replicas. Project-owned NAT gateway `sre-escalation-proxy-nat`, static public IP `sre-escalation-proxy-egress-ip`, and Storage private endpoint `sreocoxujof5ynqsregistry-table-pe` were deleted; their Bicep definitions remain the recovery source. The Standard LRS Table storage and its data, VNet/subnets, private DNS, Container Apps environment/app configuration, Log Analytics workspace, identities, role assignments, and all three SRE agents were retained. The shared Basic ACR `acrsrelabjplayn` in `rg-srelab-australiaeast` was intentionally not changed.

### WP5 Acceptance Criteria

- A routine redeployment preserves the Entra audience and all caller grants.
- Production Table traffic uses private networking under restrictive storage policy.
- The container runs non-root and uses an immutable, reproducible dependency set.
- Platform dependency failures are distinguishable from caller errors and terminal investigation failures.

## WP6: Strengthen Findings and Observability

**Goal:** Treat platform findings as a controlled data boundary and make service behavior auditable.

- [x] P6.1 Define a versioned structured final-report schema.
- [x] P6.2 Update the platform liaison to produce the structured report and completion marker.
- [x] P6.3 Parse and validate the allowlisted report fields in the proxy.
- [x] P6.4 Reject or quarantine malformed findings instead of returning arbitrary text.
- [x] P6.5 Retain defense-in-depth redaction for credentials, connection strings, signed URLs, tokens, keys, and multiline/JSON values.
- [x] P6.6 Emit safe redaction and schema-rejection metrics without sensitive values.
- [x] P6.7 Define structured audit events and metrics for authorization, admission, idempotency, quotas, latency, completion, failures, registry health, and platform dependencies. Every JSON event now carries a versioned UTC envelope; lifecycle branches emit safe outcomes, reasons, retry counts, and latency dimensions, and `docs/operations.md` defines the event catalog, prohibited fields, and Log Analytics metric queries. On 2026-09-08, immutable revision `sre-escalation-proxy--260907224914` deployed at two ready replicas and live console logs contained versioned `readiness_check_succeeded` events; the five-caller policy and healthy three-tool connector were preserved.
- [x] P6.8 Propagate one correlation ID end to end without exposing the platform thread ID.
- [x] P6.9 Add alert and dashboard guidance for security and availability signals. `docs/operations.md` defines actionable thresholds, response guidance, safe alert fields, and the standalone monitoring deployment; notification delivery remains part of P8.9.

### WP6 Acceptance Criteria

- Public findings contain only allowlisted schema fields.
- No bearer token, platform thread ID, or credential-shaped value appears in responses or logs.
- Documentation clearly distinguishes Container App Log Analytics logs from optional SRE Agent Application Insights resources.

## WP7: Reframe the Repository and Reference Consumer

**Goal:** Make the platform service the primary deliverable and the workload implementation an optional example.

- [x] P7.1 Rewrite the root README around the Platform SRE Agent and Escalation Service.
- [x] P7.2 Update architecture documentation to distinguish privileged admin access from the narrow external-agent path.
- [x] P7.3 Move the workload flow under a clearly labeled reference implementation section.
- [x] P7.4 Generalize public terminology from workload to caller or consumer while preserving `workload_name` compatibility in v1. Public errors and integration guidance now use caller-first language; MCP exposes `caller_label` while accepting matching or standalone legacy `workload_name`, and the Workload SRE Agent remains explicitly named only as the reference implementation.
- [x] P7.5 Split fixed ALZ assumptions into a sample playbook or explicit platform-owned configuration. The deployed liaison prompt now discovers topology from authorized Azure evidence and explicitly avoids assuming a hierarchy, network model, firewall, DNS design, or subscription layout. The former hub-and-spoke guidance is retained as an optional platform-owned sample playbook that is neither loaded nor deployed automatically. On 2026-09-08, the topology-neutral `workload_liaison` was published to the Platform SRE Agent; live readback returned `200`, retained the finalization contract, and contained none of the former fixed ALZ topology statements.
- [x] P7.6 Add one generic MCP client example using same-tenant application identity.
- [x] P7.7 Add one generic HTTP client example using same-tenant application identity.
- [x] P7.8 Add owner-selected LICENSE, CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, and CHANGELOG.md. The repository uses the MIT license.
- [x] P7.9 Add architecture decision records for authentication, transport, and storage.
- [x] P7.10 Archive the historical phase summary after incorporating still-relevant decisions.

### WP7 Acceptance Criteria

- A new consumer can understand and integrate with the proxy without deploying a workload SRE Agent.
- The workload example still completes create, long-poll status, and findings retrieval.
- No repository license is inferred or selected without owner approval.

## WP8: Automated Verification and Release Gate

**Goal:** Prevent contract, security, deployment, and compatibility regressions.

- [x] P8.1 Add CI for pinned dependency installation, formatting, linting, typing, and security checks.
- [x] P8.2 Run unit, HTTP contract, and registry contract suites in CI.
- [x] P8.3 Build all Bicep entry points and validate PowerShell scripts.
- [x] P8.4 Build and scan the container image.
- [x] P8.5 Check generated OpenAPI and schema compatibility.
- [x] P8.6 Remove generated ARM JSON from source control; Bicep source is authoritative and templates are rebuilt during validation.
- [x] P8.7 Add a staging end-to-end test with two independent caller identities. Overlapping WorkloadApp and WorkloadIsolation investigations completed on separate caller partitions on 2026-09-01, and a fresh simultaneous two-caller smoke passed after restoration on 2026-09-04.
- [x] P8.8 Test cross-caller denial, disabled/revoked callers, idempotency, severity, quotas, restart survival, and multi-replica access. Reciprocal cross-caller denial, same-caller quota-one rejection, terminal release/reuse, restart survival, and multi-replica access passed. On 2026-09-04, a five-caller allowlist was activated; both workload agents completed positive-path escalations, WorkloadIsolation was denied while disabled and again after revoke, WorkloadApp remained authorized as the control, re-grant recovery succeeded, and all five callers were restored on healthy revision `sre-escalation-proxy--0000020`. On 2026-09-07, the WorkloadApp connector replayed an identical request under the same idempotency key, rejected a changed payload under that key, and denied a high-severity request while its policy ceiling was temporarily set to low without admitting an investigation. The exact five-caller policy snapshot was restored with ETag protection; all four health endpoints returned `200`, and both replicas remained ready.
- [x] P8.9 Test registry and Platform SRE Agent outages against readiness, retries, public errors, metrics, and alerts. Dependency-aware readiness, bounded retry/circuit-breaker behavior, safe `503` responses, and genuine recovery were validated on 2026-09-07. On 2026-09-11, the fresh tenant deployed enabled severity-1 five-minute scheduled-query rules for policy/readiness and Platform SRE Agent dependency failures. Both rules target `sre-escalation-proxy-logs`, use the expected structured-event predicates, and route to the operator-owned `AGOwner` action group. An Azure Monitor Log Alert V2 test completed at `2026-09-11T02:12:48Z`; its enabled `chbowm@microsoft.com` email action reported `Succeeded`, and the recipient confirmed inbox delivery.
- [x] P8.10 Verify Azure SRE Agent reference connector compatibility. The fresh WorkloadApp connector completed the create/status/findings lifecycle in staging on 2026-08-27. After the 2026-09-07 runtime recovery, the connector was restored to `Connected`, healthy, with three tools. A fresh WorkloadApp-originated smoke then selected `workload-escalation-parent`, delegated to `platform-escalation`, and completed the create/status/findings lifecycle with a structured final report and no resource modifications. On 2026-09-11, the newly deployed tenant completed investigation `05b25764-3622-4c8a-9b83-a282ba1ffe5a` with correlation ID `e6b9f365-e0ed-4998-957e-2cf99a2b96ea`: create returned pending, the first status poll returned completed, and summary returned structured findings schema v1.0 with the test correctly classified as no platform issue. The platform agent also discovered the scoped `workload-rg` agent, Application Insights, Log Analytics workspace, and managed identity resources in `australiaeast`.

### V1 Release Gate

The following records the historical v1 release decision. It is not current security sign-off: the affected guarantees are reopened and must pass the post-assessment release gate below.

- [x] Immutable redeployment preserves the Entra audience and existing caller grants. Verified on 2026-09-04 with the stable client ID, app role ID, five caller grants, and both connectors intact.
- [x] Private Table access works under the target policy environment.
- [x] An official MCP SDK client passes the supported protocol flow.
- [x] The Azure SRE Agent connector passes the same three-tool flow.
- [x] HTTP OpenAPI compatibility checks pass.
- [x] Multi-replica and restart tests preserve ownership and state. Two-replica lifecycle and in-flight rolling restart survival passed on 2026-09-01.
- [x] Security scans pass or have explicitly accepted findings. CI gates dependency vulnerabilities, medium/high source findings, and fixable high/critical container findings; unfixed base-image advisories remain visible in Trivy reports, and low-severity non-cryptographic retry jitter is accepted.
- [x] Manual log inspection finds no tokens, platform thread IDs, or unredacted sensitive findings. The 2026-09-07 audit found and removed `platform_thread_id` from `platform_thread_created`; regression coverage passes, the corrected immutable image is live, and sampled current-revision lifecycle logs contain no bearer/authorization material, SAS-like values, platform thread IDs, or report bodies.

## 2026-09-11 Assessment: Remediation Backlog

All tasks below are open. Preserve the original WP1-WP8 implementation history, but do not treat their checked boxes as current acceptance for the controls mapped here. Each future implementation must add a regression that fails on the reviewed baseline, then demonstrate the repaired behavior. Use synthetic secrets and isolated test resources; obtain explicit authorization before cloud changes or production probes.

### Finding-to-Work-Item Map

| Finding | Priority and evidence | New work | Earlier acceptance reopened |
|---|---|---|---|
| F01: Expired cached caller policy accepted after refresh failure | High; locally reproduced | P9.1, P9.3 | P5.13, P8.8 |
| F02: Disabled/revoked caller can still read owned investigations | High; disabled-policy service probe | P9.2, P9.3 | P2.2, P5.3, P8.8 |
| F03: MCP/legacy returns unvalidated intermediate text and sensitive fields | High; synthetic thread ID and AccountKey values survived | P11.1-P11.3 | P2.4, P6.3-P6.6, P8.8 |
| F04: Wildcard Table ETags defeat quota/state concurrency | High; real SDK metadata and two-writer simulation | P10.1, P10.2, P10.6 | P4.2, P4.3, P8.8 |
| F05: Idempotency lookup permits OData predicate injection | High; local query capture and foreign-record return, not live findings theft | P10.3, P10.6 | P3.4, P4.1, P8.8 |
| F06: Nonatomic idempotency and uncertain POST replay | High operational risk; duplicate reservations and mocked POST retries | P10.4-P10.6 | P3.4, P4.2, P5.12, P8.8 |
| F07: Readiness and dependency error semantics are misleading | Medium; local readiness/error probes | P12.1, P12.2 | P4.6, P5.12, P8.9 |
| F08: Blocking SDK calls and unbounded summary-request amplification | Medium; source-review availability risk | P12.3, P12.4 | P5.8, P8.9 |
| F09: Private thread IDs can enter request-path telemetry | Medium; source review | P11.4 | P6.7, P6.8, manual log gate |
| F10: Per-caller platform-resource entitlement is undefined | Architectural risk; no demonstrated prompt-injection exploit | P11.5 | P1.5, P6.3, P7.2 |
| F11: Unfixed image advisories lack explicit risk disposition | Scanner evidence; application exploitability unassessed | P13.2 | P8.4, security-scan gate |
| F12: Production network/shared-key controls are not self-enforcing defaults | Deployment hardening gap; deployed tenant controls may differ | P12.5 | P5.5, P5.6 |

## WP9: Restore Fail-Closed Caller Authorization

**Goal:** Enforce fresh operator policy for every investigation operation, independently of an otherwise valid Entra token.

**Priority:** High. **Dependencies:** None; recommended first implementation package.

**Owning files:** [caller_policy.py](../escalation-proxy/app/caller_policy.py), [authorization.py](../escalation-proxy/app/authorization.py), [investigation_service.py](../escalation-proxy/app/investigation_service.py), [mcp_transport.py](../escalation-proxy/app/mcp_transport.py), and caller-policy/security tests.

- [x] P9.1 Enforce snapshot age on every policy access, including refresh-interval skips and last-known-good reads. A failed refresh must not make an expired snapshot usable on the next request. Preserve bounded refresh frequency and recovery after a valid snapshot becomes available.
- [x] P9.2 Check caller registration/enabled state in the shared service before create, idempotent replay, status, and summary access. Preserve independent token validation, ownership checks, and create-only severity admission. Disabled/missing policy must deny reads even for unexpired tokens containing `EscalationCaller`; no implicit break-glass read path.
- [x] P9.3 Add fake-clock and transport-level regressions for stale-cache boundaries, repeated requests during outages, refresh recovery, removed callers, disable/revoke with still-valid tokens, and re-enable. Exercise v1 HTTP, compatibility routes, and official MCP; verify rejection precedes upstream access.
- [x] P9.4 Document policy propagation and maximum-staleness guarantees, revoke versus token-expiry behavior, safe error mapping, and operational recovery. Update the contract and caller-administration guidance to match the verified behavior.

### WP9 Acceptance Criteria

- Reproduce the reviewed sequence: snapshot at t=100, failed refresh at t=401, maximum staleness 300 seconds, next request at t=402. Both requests deny; no refresh-interval bypass exists.
- Within the documented policy propagation bound, disabling a caller blocks all owned reads and creates across transports. An independent enabled caller continues to work.
- Missing/expired policy fails closed on every operation; a successful refresh restores access without restart. Tests cover the exact staleness boundary and repeated failures.

## WP10: Repair Registry Isolation and Creation Idempotency

**Goal:** Preserve caller isolation, accurate quotas, and one logical investigation under concurrent requests, replica failures, and uncertain upstream outcomes.

**Priority:** High. **Dependencies:** P10.1-P10.2 precede atomic-idempotency implementation; integrate WP9 authorization before replay. WP10 must precede final WP12 retry-policy acceptance.

**Owning files:** [investigation_registry.py](../escalation-proxy/app/investigation_registry.py), [investigation_service.py](../escalation-proxy/app/investigation_service.py), [platform_client.py](../escalation-proxy/app/platform_client.py), and registry/security tests.

- [x] P10.1 Read ETags from actual `TableEntity.metadata`, fail safely when a conditional mutation lacks an ETag, and remove wildcard fallbacks from quota/lifecycle/poll mutations. Handle the installed SDK's `TableTransactionError` status/error semantics as well as applicable entity conflicts; retry only genuine concurrency conflicts with bounded attempts and fresh reads.
- [x] P10.2 Audit admission, counter reconciliation, finalization, completion, release, polling, and expiry cleanup for lost updates. Use conditional same-partition transactions where needed; cleanup must not delete a concurrently renewed record. Keep counter/record transitions consistent and terminal release idempotent.
- [x] P10.3 Parameterize idempotency lookup rather than interpolating caller-controlled strings. Constrain lookup by authenticated caller partition and recheck returned ownership. Cover quote/operator injection, unexpected foreign rows, counter rows, and nonexpired record selection. Keep public errors opaque; do not claim foreign findings were stolen in the original assessment.
- [x] P10.4 Atomically claim a caller-scoped idempotency key with its canonical request fingerprint and quota reservation. Define an in-progress replay response before the upstream thread exists. Identical concurrent requests must resolve to one investigation; changed payloads conflict. Align memory and Table replay behavior for active, terminal, and retained records, including explicit key retention/expiry rules and old-row compatibility.
- [x] P10.5 Separate definitely failed creation from unknown outcomes. Do not blindly retry thread-creation POSTs or release reservations after response loss, cancellation, or registry-finalization failure. Verify upstream deduplication/reconciliation capability; if unavailable, persist a recoverable uncertain state and block duplicate creation pending bounded reconciliation/operator handling. Document crash recovery and orphan-thread disposition without promising unsupported exactly-once upstream execution.
- [ ] P10.6 Add real-SDK-shaped entity and transaction-error tests, deterministic concurrent-writer barriers, fault injection, and an explicitly authorized isolated two-replica Table test. Cover shared and distinct keys, two callers, counter conflicts, timeout-after-commit, crash before/after upstream success, finalization failure, cleanup races, and restart recovery.

### WP10 Acceptance Criteria

- With quota one, simultaneous distinct-key requests admit at most one investigation and the persisted counter matches authoritative active reservations. Independent callers are not blocked by one another.
- Two replicas using the same caller/key/payload expose one investigation and do not issue a second create while the first outcome is unknown. Changed payloads conflict; terminal replay works consistently in both backends.
- SDK-deserialized metadata produces a real conditional ETag, not `*`; stale writes retry or fail safely with no lost update or double quota release.
- Injected keys cannot alter caller scope, disclose foreign identifiers/state, or turn foreign fingerprints into an oracle. Test both repository lookup and public transport behavior.
- Every uncertain creation remains discoverable for recovery with a documented quota policy. A local transaction alone is not accepted as proof of upstream exactly-once creation.

## WP11: Enforce Findings, Telemetry, and Resource Trust Boundaries

**Goal:** Return only finalized, validated, caller-authorized findings and prevent sensitive content from leaking through compatibility paths or logs.

**Priority:** High for F03; medium telemetry hardening and an explicit architecture decision for F10. **Dependencies:** WP9 read authorization; coordinate persisted findings metadata with WP10.

**Owning files:** [investigation_service.py](../escalation-proxy/app/investigation_service.py), [output_validation.py](../escalation-proxy/app/output_validation.py), [contracts.py](../escalation-proxy/app/contracts.py), [main.py](../escalation-proxy/app/main.py), [mcp_transport.py](../escalation-proxy/app/mcp_transport.py), [telemetry.py](../escalation-proxy/app/telemetry.py), [platform_client.py](../escalation-proxy/app/platform_client.py), and the platform liaison/architecture/threat-model documents.

- [x] P11.1 Put finalization, schema validation, and safe projection in the shared summary path used by official MCP, legacy MCP/HTTP, and v1 HTTP. Pending/running responses must not include intermediate agent prose. Malformed completed reports produce a safe contract error, not fallback raw text. Preserve wrappers only when their content satisfies this boundary; document intentional security-related compatibility changes.
- [x] P11.2 Strengthen finalization parsing to the documented report structure and final marker position; reject marker substrings embedded in evidence, incomplete sections, and mixed intermediate/final messages. Model output remains untrusted even when it has the marker. Emit only allowlisted fields with validated types.
- [x] P11.3 Extend defensive redaction/validation to complete connection strings, AccountKey and related credential forms, multiline/JSON content, signed URLs, and internal thread identifiers embedded in otherwise valid fields. Use structured parsing where applicable and reject unsafe output when needed; do not represent regex redaction as comprehensive data-loss prevention.
- [x] P11.4 Replace private thread-bearing request paths with route templates in telemetry; allowlist safe event fields and sanitize untrusted request IDs/methods and exception data. Audit success, retry, failure, and transport logging, not only `platform_thread_created`. Keep correlation via public investigation/correlation IDs without persisting report content.
- [x] P11.5 Decide and document whether callers share entitlement to all readable platform data or require per-caller resource restrictions. ADR 004 records the accepted boundary: callers name one App Configuration-allowlisted workload group; the Platform SRE Agent retains platform-only RBAC; detailed reports stay in platform-owned threads; and every verdict is replaced by fixed proxy-authored guidance. Out-of-scope admission and all-verdict non-disclosure regressions enforce the boundary independently of prompt text.
- [x] P11.6 Add a shared response/log corpus with synthetic credentials, private identifiers, forged markers, malformed reports, and intermediate messages across every transport. Include official-client and reference-connector compatibility checks against the controlled findings contract.

### WP11 Acceptance Criteria

- The reviewed intermediate-message example containing `platform_thread_id`, `AccountKey`, and semicolon-separated connection-string fields is never returned as findings.
- All transports reject malformed final reports and expose only validated final fields; no pre-finalization prose escapes. Safe complete findings still work through the reference connector.
- Captured logs for success and all failure/retry paths contain no synthetic secrets, private thread IDs, or report bodies, including identifiers embedded in request paths.
- The supported caller-resource trust model has an explicit decision and enforceable tests. Cross-caller record ownership is not substituted for platform-resource authorization.

## WP12: Bound Availability Risks and Enforce Deployment Controls

**Goal:** Make readiness and failure responses truthful, bound request amplification, and make production safeguards reproducible without relying on tenant policy.

**Priority:** Medium. **Dependencies:** WP9 policy health behavior; WP10 for creation retry semantics. Infrastructure changes and staging fault injection require separate deployment authorization.

**Owning files:** [main.py](../escalation-proxy/app/main.py), [platform_client.py](../escalation-proxy/app/platform_client.py), [caller_policy.py](../escalation-proxy/app/caller_policy.py), [investigation_registry.py](../escalation-proxy/app/investigation_registry.py), [authorization.py](../escalation-proxy/app/authorization.py), [proxy infrastructure](../escalation-proxy/infrastructure/main.bicep), deployment scripts, monitoring definitions, and operations guidance.

- [ ] P12.1 Make readiness check bounded platform authentication and non-mutating connectivity, registry availability, acceptable policy freshness, and relevant circuit state. Local cache/deadline regressions pass, including cancellation at the application boundary, and production infrastructure now passes a bounded per-dependency timeout. Authorized private-Table staging must still confirm cold startup stays within the Container Apps probe budget and recovers without restart.
- [x] P12.2 Map policy, registry, and platform unavailability to stable safe dependency codes with `503` and `retryable: true` where appropriate. Distinguish malformed output, caller errors, rate limits, and terminal investigation failure. Bound retry latency and retry only permitted transient failures; nonretryable 4xx responses must not loop through generic exception handling. Align HTTP/MCP guidance with WP10's uncertain-create contract.
- [x] P12.3 Move synchronous JWKS, managed-identity, App Configuration, and Table operations off the async event loop using supported async clients or bounded offloading. Preserve locks/transactions correctly, bound timeouts and concurrency, and reuse clients safely. Assess unknown-key JWKS refresh amplification without weakening signature verification.
- [x] P12.4 Apply bounded admission to summary retrieval as well as status. Summary intervals and counts are persisted with conditional Table updates across replicas; platform-call concurrency and queue time are bounded per replica; request and platform-response bytes are capped; and only a bounded number of recent agent messages is parsed. Rate and capacity exhaustion return safe errors before additional upstream work.
- [x] P12.5 Make the production profile explicitly disable Storage shared-key and public-network access and require the private Table path. The Bicep default now enables private networking for Table mode, the deployment script rejects Table mode without `-EnablePrivateNetworking`, and the operator guide documents memory mode as the local smoke option. Evaluate App Configuration network access and required Entra/platform egress; document justified exceptions and dev-only opt-outs. Preserve existing stable identities and grants.
- [ ] P12.6 Validate dependency outages/recovery, circuit transitions, retry classification, slow SDK calls, repeated readiness, oversized inputs, and summary bursts in isolated tests. Check alert predicates against real failure events and retain existing notification-delivery evidence separately from dependency-detection proof.

### WP12 Acceptance Criteria

- Simulated platform unreachability or an open dependency circuit yields readiness `503` within a documented budget; liveness remains available. Recovery restores readiness without restart.
- Dependency responses carry the documented retryable code and no internal exception details. Nonretryable upstream errors are not retried; uncertain creates obey WP10.
- Slow SDK responses and abusive summary/health traffic do not block the event loop or starve an independent caller within measured, documented limits.
- Compiled production infrastructure enforces storage authentication/network controls without tenant-policy assistance; authorized staging verifies private DNS/egress and preserved identities.

## WP13: Reopen Verification and Security Sign-Off

**Goal:** Replace the previous green-suite inference with evidence covering the actual failure modes and explicit residual-risk decisions.

**Priority:** Required release gate. **Dependencies:** WP9-WP12; image triage can begin independently.

- [ ] P13.1 Add WP9-WP12 regressions to CI with both registry contracts, real SDK response/error shapes, deterministic concurrency/fault tests, and all public transports. The named `post-assessment-regressions` CI job now runs the high-risk authorization, isolation, idempotency, uncertain-outcome, Table SDK, findings, readiness, availability, and official MCP selectors; the full suite remains in the standard test job. Cloud Table fault injection and two-replica evidence remain under P13.3. Record baseline failures and repaired passes; dictionary-only ETag mocks and sequential idempotency tests are insufficient. Retain existing lint/type/security/build/schema gates.
- [x] P13.2 Rescan the exact candidate image digest, including unfixed vulnerabilities and applicable platforms. The Debian-based digest had 51 HIGH and 3 CRITICAL OS package/advisory occurrences with no upstream fixes. Commit `c8287f7` moved to pinned `python:3.12-alpine`, applied available `apk` security updates, and retained non-root execution. Trivy 0.74.0 reported zero HIGH/CRITICAL findings for final deployed digest `sha256:76497dd794b33f3422e29d5f9a9a3f7345169e5847ff9e1271761ee5a816667d`; `pip-audit` reported no known Python dependency vulnerabilities.
- [ ] P13.3 With separate authorization, validate the candidate in isolated private-Table staging with two replicas and two caller identities. Exercise revocation with unexpired tokens, query injection, simultaneous quota/key claims, uncertain-create recovery, restart, malformed findings, outage semantics, and safe telemetry. No destructive production probes.
- [x] P13.4 Reconcile the service contract, threat model, operations guide, release notes, and prior acceptance claims with observed behavior. The service contract now distinguishes strict internal liaison Markdown from caller-safe JSON; architecture diagrams show the private Table/App Configuration dependencies; operations guidance covers Standard-tier private App Configuration and private operator administration; the threat model covers policy-store public-path outage; and the Unreleased changelog records the compatibility, network, and readiness changes. Document compatibility changes, policy bounds, recovery procedures, caller trust assumptions, and residual risk without embedding secrets or raw findings in evidence.
- [ ] P13.5 Record a finding-by-finding closure decision with commit/image digest, test commands/results, staging evidence where required, and reviewer/operator approval. Do not close a finding solely because the original 94 tests still pass. Plan any rollout/rollback separately; do not retag the reviewed release as though it contained the fixes.

### Post-Assessment Release Gate

Broader rollout is recommended only after this gate passes. Package task completion requires recorded evidence; explicit risk acceptance is required for any residual deployment/image risk, not an unchecked assumption.

- [ ] F01-F06 remediated with baseline-failing regressions and successful repaired verification across the affected transports/backends.
- [ ] F07-F09 and F12 controls validated, including bounded load/outage behavior, safe telemetry, and policy-independent production infrastructure.
- [ ] F10 caller-resource trust decision approved and enforced for every supported onboarding model.
- [ ] F11 candidate-digest scan complete; all HIGH/CRITICAL findings fixed or individually dispositioned with time-bounded owner approval and evidence.
- [ ] Independent-caller, multi-replica, restart, uncertain-outcome, and reference-connector staging checks pass with no foreign data or synthetic-secret disclosure.
- [ ] Documentation and compatibility guidance agree with tested behavior; closure record identifies reviewer, candidate commit/digest, and any residual limitations.

## Affected Files

- `escalation-proxy/app/main.py`
- `escalation-proxy/app/test_security.py`
- `escalation-proxy/app/requirements.txt`
- `escalation-proxy/app/Dockerfile`
- `escalation-proxy/infrastructure/main.bicep`
- `scripts/deploy-escalation-proxy.ps1`
- `scripts/grant-workload-escalation.ps1`
- `modules/mcp-connector-streamable-http.bicep`
- `platform/custom-agents/workload-liaison.yaml`
- `workload/custom-agents/platform-escalation.yaml`
- `README.md`
- `escalation-proxy/README.md`
- `docs/architecture.md`
- `docs/detailed-spec.md`
- `docs/threat-model.md`
- `.github/workflows/*`
- `LICENSE`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `CHANGELOG.md`

## Verification Strategy

1. Run proxy unit and contract tests against both memory and Table registry implementations.
2. Run an official MCP SDK client against `/mcp` for initialization, discovery, calls, authorization, malformed requests, and reconnect behavior.
3. Run HTTP schema checks and the full lifecycle through a generic same-tenant caller.
4. Build every Bicep entry point and run static deployment-policy checks.
5. Deploy staging with at least two replicas and two caller identities.
6. Verify the Azure SRE workload reference connector end to end.
7. Simulate registry and Platform SRE Agent outages.
8. Run dependency, container, and IaC security scans and inspect logs for sensitive data.

## Deferred Decisions

1. APIM may later provide centralized governance and analytics but is not required for v1.
2. Cross-tenant callers require a separate design because they change issuer validation, tenant allowlisting, onboarding, abuse controls, and support obligations.

## Decision Log

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-26 | Support same-tenant service identities in v1 | Preserves a clear, testable authorization boundary for the first reusable release. |
| 2026-08-26 | Support both MCP and asynchronous HTTP | MCP serves agent frameworks while HTTP provides a portable fallback and integration contract. |
| 2026-08-26 | Keep the workload SRE Agent as a reference consumer | Demonstrates Azure SRE integration without coupling the platform service to that caller. |
| 2026-08-26 | Keep Azure Table Storage as the first production registry | Builds on the existing implementation while requiring private networking and atomic semantics before release. |