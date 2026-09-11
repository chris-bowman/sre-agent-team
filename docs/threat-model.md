# Escalation Proxy Threat Model

Last reviewed: 2026-09-11

## Scope

This model covers the workload SRE agent, the escalation proxy, the Platform SRE
Agent, Entra ID tokens, and the resource groups inspected by the workload agent.
The proxy is a trust boundary: workload evidence is untrusted input, while the
proxy's managed identity can call the platform agent.

## Assets

| Asset | Required protection |
|---|---|
| Investigation ownership and findings | Workload isolation and confidentiality |
| Platform agent thread IDs | Must not be exposed to workload callers |
| Entra bearer tokens and claims | Authentication, integrity, and no log disclosure |
| Platform agent privileges | Least privilege and resource scoping |
| Audit events | Integrity, availability, and useful retention |
| Workload resource data | Access only within declared resource groups |

## Trust Boundaries

1. Workload agent to proxy: authenticated Entra application token; request fields
   and diagnostic evidence are untrusted.
2. Proxy to Platform SRE Agent: proxy managed identity and platform-agent role.
3. Workload agent to Azure resources: workload managed identity with Reader and
   Monitoring Reader roles only in the configured resource groups.
4. Proxy to telemetry: operational logs must not contain credentials or raw
   bearer tokens.

## Threats and Controls

| Threat | Control | Residual risk |
|---|---|---|
| Cross-workload investigation access | Registry ownership check uses caller app ID; status and summary resolve opaque IDs to platform thread IDs; production uses shared Table state | Memory mode remains local-only and single-replica |
| Forged or underprivileged caller | JWT signature, issuer, audience, required app role, `appid`, and `oid` validation | JWKS and Entra availability affect requests |
| Severity privilege escalation | Allowed severity set plus operator-owned caller policy severity ceiling | Caller policy administration must remain restricted and auditable |
| Prompt injection in evidence | Delimited untrusted evidence and explicit routing/completion contracts | The platform agent must honor the contract |
| Secret disclosure in findings | Credential-shaped values are redacted before summary return | Pattern-based redaction can miss novel formats |
| Polling denial of service | Per-investigation interval/count limits plus caller concurrency policy | No service-wide distributed request-rate limiter yet |
| Caller quota exhaustion | Atomic per-caller Table counter, reservation lifecycle, stale-counter reconciliation, and terminal slot release | Memory mode remains process-local and non-production |
| Platform thread probing | External opaque investigation IDs and registry lookup | Compromise of the proxy remains high impact |
| Internal error disclosure | Generic MCP response for unhandled exceptions; detailed event is server-side only | Logs require protected access and retention |
| Over-broad workload inspection | RBAC assignments loop over explicit `scopedResourceGroups` | Resource groups must be validated operationally |
| Replay of an investigation request | Caller-scoped idempotency keys and request fingerprints persisted with investigation state | Clients must retain and correctly reuse idempotency keys |
| Caller requests an unrelated resource group | App Configuration policy contains canonical `allowed_resource_groups`; each create request supplies one authorized group and is denied before platform access when it is not allowlisted | This routing boundary does not reduce the privileged platform agent's underlying Azure RBAC |
| Platform details disclosed to a workload caller | Finalized structured output and verdict are validated centrally; every verdict is replaced with fixed proxy-authored ownership and handoff guidance | Detailed findings remain sensitive platform-thread data and require protected operator access |
| Event-loop starvation | JWT/JWKS, managed identity, App Configuration, and Table calls use a bounded offloader; upstream platform calls have bounded per-replica admission and queue time | Limits are per replica rather than globally distributed |

## Security Invariants

- A caller can read status or findings only when its workload app ID owns the
  investigation.
- No workload response contains the platform thread ID, bearer token, or raw
  credential-shaped value.
- A requested severity cannot exceed the token's declared ceiling when that
  claim is configured as required.
- The workload agent has no platform-agent administrator role.
- All authorization failures and sensitive access events are auditable without
  recording secrets.
- A new investigation names exactly one operator-allowlisted workload resource
  group. Platform-owned outcomes disclose only a generic handoff to the caller.

## Verification Plan

- Run `pytest escalation-proxy/app -q` for ownership, quotas, validation,
  idempotency, redaction, and caller-policy tests.
- Build `workload/main.bicep` before deployment.
- In staging, verify two workload identities cannot exchange investigation IDs.
- Inspect telemetry for `investigation_access_denied`, quota, and redaction
  events without exposing token values.
- Validate production Table state across at least two replicas and a rolling
  revision restart, including reciprocal cross-caller denial and terminal quota release.

## Open Decisions for the Next Phase

1. Complete the authorized two-caller/two-replica adversarial staging suite,
  including unexpired-token revocation and uncertain-create fault injection.
2. Evaluate separate platform agents or a trusted tool broker for organizations
  requiring per-caller isolation within platform-owned tool scope.
3. Evaluate a distributed caller/service rate limiter if per-replica admission
  is insufficient at the configured maximum scale.
