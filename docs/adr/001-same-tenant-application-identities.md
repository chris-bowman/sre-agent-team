# ADR 001: Same-Tenant Application Identities

## Status

Accepted

## Decision

Version 1 accepts only same-tenant, app-only Entra access tokens carrying the `EscalationCaller` application role. The validated application ID is the caller ownership and policy key.

## Consequences

- External callers do not receive Platform SRE Agent administrative permissions.
- Delegated-user tokens and cross-tenant callers require a separate future design.
- Caller labels are display metadata only and never grant authorization.