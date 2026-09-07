# Changelog

All notable changes to this project are documented here. The project follows Keep a Changelog conventions and intends to use semantic versioning when releases begin.

## Unreleased

### Added

- Repository-wide Bicep and PowerShell validation in CI.
- Platform SRE Agent circuit breaker with bounded recovery behavior.
- MCP create-tool idempotency-key support.
- Azure App Configuration-backed dynamic caller policy with managed-identity access, ETag updates, revision metadata, last-known-good caching, and fail-closed staleness handling.
- Repository governance and production operations guidance.

### Security

- Dynamic caller-policy changes no longer require Container App revisions.
- Empty or unavailable dynamic policy denies callers while static empty configuration remains available for local development.
