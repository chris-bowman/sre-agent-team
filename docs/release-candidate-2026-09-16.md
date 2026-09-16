# Release Candidate Evidence: 2026-09-16

## Candidate

- Source commits: `df2a6bb`, `1dcbbc6`, `5a1b37a`
- Container App revision: `sre-escalation-proxy--0000029`
- Immutable image: `acrsrebf3a76f2.azurecr.io/sre-escalation-proxy@sha256:75ce9734a2aeaa1bb1cdad0ff41de8ae5a71af92de3c8c8ae223d08f2aacbd51`
- Registry profile: Azure Table Storage with private networking
- Scale profile: two healthy replicas

## Automated Evidence

- Full application gate: Ruff format and lint, mypy, Bandit, compileall, and `141 passed` pytest tests.
- Post-assessment CI-equivalent selectors: `34 passed` for authorization/isolation/idempotency/Table coverage; `38 passed` for findings/readiness/availability/MCP coverage.
- Deployment artifacts: Bicep compilation, PowerShell parser validation, and `git diff --check` passed.
- Image scan: Trivy scanned the exact deployed digest with HIGH/CRITICAL and unfixed findings included; zero vulnerabilities were reported for Alpine 3.24.1 and detected Python packages.

## Runtime Evidence

- `/health/live`, `/health/ready`, and `/mcp/` returned `200` after deployment.
- Twelve independent readiness samples returned `200` in 1.04 to 1.65 seconds. The Container Apps readiness timeout is 20 seconds and the application deadline is 15 seconds.
- Recent proxy logs contained no `ERROR`, `Traceback`, readiness failure, caller-policy refresh failure, or reconciliation failure events.
- Under a temporary WorkloadApp quota of one, `eac6c7a7-1203-431e-890a-ca2f2fae945d` was admitted and intentionally left unpolled. The proxy's background worker observed it as running on four one-minute sweeps, detected completion at `2026-09-16T02:37:43Z`, and emitted `investigation_reconciled` without any caller status or summary request. A subsequent WorkloadApp investigation, `e9c58ed3-da3e-44ed-b5e3-1b8034b0bb38`, was admitted under the same quota, proving the terminal slot was automatically reusable. WorkloadApp quota was restored to ten through an ETag-protected private App Configuration update.
- WorkloadIsolation's policy was disabled while its existing `EscalationCaller` Entra assignment remained intact. After the proxy loaded the disabled snapshot, its create request returned the expected safe `403` caller-policy denial. The policy was then re-enabled through the same private ETag-protected path; `3f6027af-67c7-4e26-ad96-2ec27721be99` was admitted immediately afterward, proving recovery without an Entra role change.
- WorkloadApp requested status and summary for WorkloadIsolation investigation `3f6027af-67c7-4e26-ad96-2ec27721be99` after the opaque lookup correction was deployed to healthy two-replica revision `sre-escalation-proxy--0000032` (`sha256:6ceb7068994ecfe03c6b5c52d63ef069251c65764703be1118f03661cb926dc5`). Both calls returned exactly `404 Investigation not found`, with no foreign lifecycle, findings, or identifier detail disclosed.
- WorkloadApp idempotency validation passed: initial create returned `d1d360bc-faf9-4ab0-bafa-c9d33ed42b60`; an exact repeat using the same key and fields returned that same ID without another platform create; reusing the key with only the description changed returned `409 Idempotency key was used with a different request`.
- WorkloadApp investigation `77401afb-f225-4eee-847d-8baf14aec626` was created before a scoped rolling proxy restart. The replacement revision `sre-escalation-proxy--p13restart20260916153118` became latest-ready with two healthy replicas on the same immutable digest `sha256:6ceb7068994ecfe03c6b5c52d63ef069251c65764703be1118f03661cb926dc5`; liveness, readiness, and MCP returned `200`. After replacement, the original ID completed and returned the caller-safe `APPLICATION ISSUE` result, proving Table-backed state survived the restart.
- WorkloadApp created `2bb20fbe-fb3d-44bc-9603-0977594518bc` using the literal idempotency key `p13-injection' or caller_appid eq 'a413478f-1cda-4eb6-aa72-794b91fde330`. The request created a new WorkloadApp investigation and disclosed no WorkloadIsolation record, state, findings, or identifier, proving the key was not interpreted as an OData predicate.

## Remediated Candidate Controls

- Terminal reconciliation conditionally leases active investigations, detects platform terminal status without caller polling, and releases quota atomically.
- Table quota-one concurrent admissions are deterministically tested against a forced ETag conflict.
- A response timeout after a Table transaction is recovered only after caller-partition read-back proves the exact reservation, idempotency fingerprint, and reserved state committed.
- Concurrent readiness probes coalesce dependency work through the readiness cache and lock.

## Release Decision Hold

This is a deployable release candidate, not an approved broader rollout. P13.3 still requires authorized private-Table staging evidence for the two-caller matrix: unexpired-token revocation, query injection, concurrent same/different-key claims, uncertain creation, rolling restart, malformed findings, outage/recovery, and no-poll reconciler cleanup. P13.5 requires the named operator/reviewer to approve the finding-by-finding closure after that evidence is recorded.