# Changelog

All notable changes to this project are documented here. The project follows Keep a Changelog conventions and Semantic Versioning.

## [Unreleased]

### Added

- App Configuration-backed per-caller resource-group allowlists with one required scope per investigation.
- Bounded offloading for JWT/JWKS, managed identity, App Configuration, and Table SDK calls, plus bounded Platform SRE Agent request admission.

### Security

- Platform-owned findings are reduced to a caller-safe platform-team handoff.
- The runtime image now uses a pinned, patched Alpine base. The exact deployed candidate digest has zero HIGH/CRITICAL Trivy findings and the pinned Python dependency graph passes `pip-audit`.

## [1.0.0] - 2026-09-11

### Added

- Standards-compliant MCP Streamable HTTP and versioned asynchronous HTTP investigation contracts.
- Azure Table Storage investigation registry with private networking, atomic caller quotas, idempotency, retention tiers, and periodic cleanup.
- Same-tenant Microsoft Entra application authorization with stable app roles and operator-managed caller lifecycle tooling.
- Dependency-aware health checks, bounded Platform SRE Agent retries, circuit breaking, structured audit events, and Azure Monitor outage alerts.
- Reusable Platform SRE Agent service deployment with a Workload SRE Agent reference consumer.
- Repository-wide Bicep and PowerShell validation in CI.
- Azure App Configuration-backed dynamic caller policy with managed-identity access, ETag updates, revision metadata, last-known-good caching, and fail-closed staleness handling.
- Standalone read-only deployment prerequisite validation for tooling, Azure permissions, providers, regional availability, networking features, ACR, and Bicep.
- Repository governance and production operations guidance.

### Changed

- Deployments preserve the Entra audience and caller grants, resolve container tags to immutable image digests, and keep Entra bootstrap separate from routine proxy deployment.
- Investigation findings use a versioned structured schema and redact credential-shaped or platform-internal values.

### Fixed

- Managed-identity token validation and fresh-tenant deployment behavior, including empty initial app-role assignments and Windows ACR build log handling.
- Table registry lifecycle races involving ETags, terminal quota release, restart recovery, and multi-replica access.

### Security

- Dynamic caller-policy changes no longer require Container App revisions.
- Empty or unavailable dynamic policy denies callers while static empty configuration remains available for local development.
- Caller identity, ownership, severity, quota, idempotency, disabled/revoked access, and cross-caller isolation are enforced consistently across MCP and HTTP transports.
