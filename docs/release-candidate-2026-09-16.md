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

## Remediated Candidate Controls

- Terminal reconciliation conditionally leases active investigations, detects platform terminal status without caller polling, and releases quota atomically.
- Table quota-one concurrent admissions are deterministically tested against a forced ETag conflict.
- A response timeout after a Table transaction is recovered only after caller-partition read-back proves the exact reservation, idempotency fingerprint, and reserved state committed.
- Concurrent readiness probes coalesce dependency work through the readiness cache and lock.

## Release Decision Hold

This is a deployable release candidate, not an approved broader rollout. P13.3 still requires authorized private-Table staging evidence for the two-caller matrix: unexpired-token revocation, query injection, concurrent same/different-key claims, uncertain creation, rolling restart, malformed findings, outage/recovery, and no-poll reconciler cleanup. P13.5 requires the named operator/reviewer to approve the finding-by-finding closure after that evidence is recorded.