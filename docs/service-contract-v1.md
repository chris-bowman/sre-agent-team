# Platform Escalation Service Contract v1

## Document Status

- Status: Approved implementation baseline
- Contract version: `1.0`
- HTTP base path: `/api/v1`
- MCP transport path: `/mcp/`
- Authentication profile: same-tenant application identity

This document is the normative v1 contract for the Platform Escalation Service. Where older documentation or current implementation behavior differs, this contract defines the target behavior. Compatibility routes remain available during the migration window described below.

## Public Terminology

The service uses **caller** for an authenticated application identity and **consumer** for an integrating agent or service. **Workload SRE Agent** refers only to the optional reference implementation, while **workload** may still describe the Azure resources being investigated. The legacy `workload_name` field remains a deprecated v1 alias for `caller_label`; it is display metadata and does not identify or authorize a caller.

## Product Boundary

The Platform Escalation Service lets an authorized external agent request an investigation from a privileged Platform SRE Agent. It deliberately exposes only an asynchronous investigation lifecycle:

1. Create an investigation.
2. Retrieve or wait for its status.
3. Retrieve its final findings.

The service owns the mapping from public investigation IDs to private Platform SRE Agent thread IDs. Callers never receive or address platform thread IDs directly.

### Supported Operations

| Capability | v1 support | Notes |
|---|---:|---|
| Create a platform investigation | Yes | Subject to caller policy, validation, idempotency, and quota. |
| Get investigation status | Yes | Immediate or bounded server-side long polling. |
| Get final findings | Yes | Returns only validated and redacted public fields. |
| Same-tenant app-only identity | Yes | Required for all investigation operations. |
| MCP Streamable HTTP | Yes | Official MCP protocol transport at `/mcp`. |
| Asynchronous HTTP API | Yes | Versioned routes under `/api/v1`. |
| Workload SRE Agent caller | Yes | Maintained as a reference consumer. |
| Generic service or agent caller | Yes | No dependency on the workload reference implementation. |
| Delegated user tokens | No | Excluded from v1. |
| Cross-tenant callers | No | Requires a separate identity and abuse-control design. |
| Anonymous access | No | Health endpoints are the only unauthenticated surface. |
| Platform remediation or mutation | No | Investigation-only boundary. |
| Platform SRE Agent administration | No | Reserved for platform operators and the proxy identity. |
| Direct caller access to platform threads | No | Thread IDs are private service data. |

## Authentication and Caller Identity

Investigation operations require an Entra access token issued by the service tenant for the proxy application audience. The service validates all of the following before dispatch:

- token signature and signing key
- issuer and tenant
- audience
- token lifetime
- app-only token shape
- `EscalationCaller` application role
- application ID (`appid`)
- service-principal object ID (`oid`)
- enabled caller registration

The validated `appid` is the stable authorization and ownership key. The `oid` is retained for audit because service-principal objects may be recreated. A caller-supplied `workload_name` or `caller_label` is untrusted display metadata and never establishes ownership or access.

Authentication occurs once per request. The resulting verified identity is passed to the domain service and must not be reconstructed from an unverified token decode.

## Caller Registration Policy

Platform operators own a registration for each allowed caller. A registration has the following canonical shape:

```json
{
  "schema_version": "1.0",
  "caller_appid": "00000000-0000-0000-0000-000000000001",
  "display_name": "Payments production SRE",
  "enabled": true,
  "maximum_severity": "high",
  "maximum_concurrent_investigations": 3,
  "allowed_resource_groups": [
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/payments-prod"
  ],
  "created_at": "2026-08-26T18:42:00Z",
  "created_by": "platform-operator@example.com",
  "updated_at": "2026-08-26T18:42:00Z",
  "updated_by": "platform-operator@example.com"
}
```

Required policy behavior:

- A missing, disabled, or revoked registration denies new investigations.
- Ownership checks use the validated caller `appid` captured on creation.
- `maximum_severity` is an ordered ceiling: `low`, `medium`, `high`, `critical`.
- Concurrent quota counts non-terminal, non-expired investigations for that caller.
- `allowed_resource_groups` is an operator-owned allowlist of canonical Azure resource-group IDs. New investigations require exactly one allowed `resource_group_id`; missing or unauthorized scopes are denied.
- Platform-owned findings return a bounded handoff notice only. Platform root cause, evidence, and remediation detail remain with the platform team.
- The effective policy is snapshotted on creation for audit; disabling a caller still denies subsequent reads unless an operator explicitly chooses a break-glass recovery path.
- Operator identity and timestamps are audit metadata and are not exposed to callers.

## Canonical Domain Types

All timestamps use UTC RFC 3339 strings. Unknown response fields may be added in a backward-compatible minor revision; callers must ignore fields they do not recognize. Required fields cannot be removed or change type within v1.

### Investigation Status

Allowed values are:

- `pending`: accepted but not yet actively processing
- `running`: platform investigation is active
- `completed`: final findings passed validation and are available
- `failed`: investigation reached a terminal failure
- `expired`: retained metadata has exceeded its access lifetime

`completed`, `failed`, and `expired` are terminal states.

### Create Investigation Request

```json
{
  "description": "The caller cannot resolve the shared API private endpoint.",
  "caller_label": "payments-prod",
  "resource_group_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/payments-prod",
  "severity": "high",
  "context": "Failure began after the 16:00 UTC network deployment."
}
```

| Field | Type | Required | Constraints |
|---|---|---:|---|
| `description` | string | Yes | Non-empty; maximum is service-configured and published in OpenAPI/tool schema. |
| `caller_label` | string | Yes | Untrusted display label; non-empty. |
| `resource_group_id` | Azure resource-group ID | Yes | One canonical resource-group ID from the caller's operator-owned `allowed_resource_groups` policy. It guides the investigation; it does not grant caller access to platform resources. |
| `severity` | string | No | `low`, `medium`, `high`, or `critical`; defaults to `medium`. |
| `context` | string | No | Untrusted diagnostic evidence; defaults to an empty string. |

During the v1 compatibility window, `workload_name` is accepted as an alias for `caller_label`. Supplying both with different values returns `invalid_request`.

When the final verdict is `PLATFORM ISSUE`, the caller-visible findings are intentionally reduced to a handoff notice. Platform resource names, topology, root cause, evidence, and remediation remain restricted to the platform team.

### Investigation Lifecycle Response

Creation and status retrieval return the same canonical lifecycle shape:

```json
{
  "schema_version": "1.0",
  "investigation_id": "f57afdb4-348f-40aa-b29d-886f4bce5332",
  "status": "running",
  "created_at": "2026-08-26T18:42:00Z",
  "updated_at": "2026-08-26T18:43:12Z",
  "expires_at": "2026-08-27T18:42:00Z",
  "correlation_id": "4db79a5a-6ba6-4c11-9090-5d62286e7cb3",
  "poll_after_seconds": 30
}
```

| Field | Type | Required | Notes |
|---|---|---:|---|
| `schema_version` | string | Yes | Always `1.0` for this contract. |
| `investigation_id` | UUID string | Yes | Opaque caller-scoped identifier. |
| `status` | enum | Yes | Canonical investigation status. |
| `created_at` | timestamp | Yes | Creation time. |
| `updated_at` | timestamp | Yes | Last observed lifecycle change. |
| `expires_at` | timestamp | Yes | Time after which caller access is no longer guaranteed. |
| `correlation_id` | UUID string | Yes | Safe end-to-end support correlation value. |
| `poll_after_seconds` | integer | Yes | Minimum recommended delay before another status request. |
| `failure` | problem object | No | Present only when `status` is `failed`. |

### Investigation Findings Response

```json
{
  "schema_version": "1.0",
  "investigation_id": "f57afdb4-348f-40aa-b29d-886f4bce5332",
  "status": "completed",
  "created_at": "2026-08-26T18:42:00Z",
  "completed_at": "2026-08-26T18:47:31Z",
  "expires_at": "2026-08-27T18:42:00Z",
  "correlation_id": "4db79a5a-6ba6-4c11-9090-5d62286e7cb3",
  "findings": {
    "summary": "Private DNS resolution failed for the shared endpoint.",
    "impact": "The caller could not establish connections to the shared API.",
    "evidence": [
      "The private DNS zone was not linked to the caller virtual network."
    ],
    "likely_causes": [
      "The network deployment removed the virtual network link."
    ],
    "recommended_actions": [
      "Ask the platform network owner to restore and validate the virtual network link."
    ],
    "limitations": [
      "The proxy did not modify the network configuration."
    ]
  }
}
```

The public `findings` object contains only these allowlisted fields:

| Field | Type | Required |
|---|---|---:|
| `summary` | string | Yes |
| `impact` | string | Yes |
| `evidence` | array of strings | Yes |
| `likely_causes` | array of strings | Yes |
| `recommended_actions` | array of strings | Yes |
| `limitations` | array of strings | Yes |

The service validates and redacts findings before storage or return. Malformed platform output never passes through as arbitrary public text. A findings request made before completion returns `investigation_not_complete`.

### Problem Details

HTTP errors use `application/problem+json` and this stable shape:

```json
{
  "type": "https://github.com/microsoft/sre-agent-team/problems/quota-exceeded",
  "title": "Concurrent investigation quota exceeded",
  "status": 429,
  "code": "quota_exceeded",
  "detail": "The caller has reached its concurrent investigation limit.",
  "correlation_id": "4db79a5a-6ba6-4c11-9090-5d62286e7cb3",
  "retryable": true,
  "retry_after_seconds": 60
}
```

The `type` URI is an identifier and need not be dereferenceable in v1. Public details are predefined and contain no exception text, token claims, platform response bodies, internal resource IDs, or platform thread IDs.

| Code | HTTP status | Retryable | Meaning |
|---|---:|---:|---|
| `authentication_required` | 401 | No | Bearer authentication is absent or malformed. |
| `caller_not_authorized` | 403 | No | Token, role, tenant, audience, or registration is not allowed. |
| `investigation_access_denied` | 403 | No | Investigation is not owned by the caller. |
| `investigation_not_found` | 404 | No | No caller-visible investigation exists for the ID. |
| `investigation_not_complete` | 409 | Yes | Findings are not yet available. |
| `idempotency_conflict` | 409 | No | A key was reused with a different request payload. |
| `invalid_request` | 422 | No | Request fields failed contract validation. |
| `severity_not_allowed` | 422 | No | Requested severity exceeds caller policy. |
| `quota_exceeded` | 429 | Yes | Caller concurrent quota is exhausted. |
| `poll_rate_exceeded` | 429 | Yes | Caller polled earlier than instructed. |
| `platform_unavailable` | 502 | Yes | Platform SRE Agent returned an invalid response. |
| `dependency_unavailable` | 503 | Yes | Registry, identity, or platform dependency is unavailable. |
| `investigation_timeout` | 504 | Yes | A bounded platform operation exceeded its deadline. |
| `internal_error` | 500 | No | Unexpected service failure with no internal details exposed. |

To avoid ownership enumeration, an implementation may return `investigation_not_found` instead of `investigation_access_denied`; it must do so consistently across HTTP and MCP.

## HTTP API

### Create

`POST /api/v1/investigations`

Headers:

- `Authorization: Bearer <token>`
- `Idempotency-Key: <caller-generated opaque value>` (required)
- `Content-Type: application/json`

Success returns `202 Accepted`, the lifecycle response body, a `Location` header for the status resource, and `Retry-After` matching `poll_after_seconds`.

An idempotency key is scoped to the validated caller `appid`. Repeating the same key and canonical request returns the original response. Reusing the key with a different canonical request returns `idempotency_conflict`.

### Get Status

`GET /api/v1/investigations/{investigation_id}`

Optional query parameter:

- `wait_seconds`: integer from `0` to the server-published maximum; defaults to `0`

Success returns `200 OK`, the lifecycle response body, and `Retry-After` for non-terminal states. Long polling may return before the requested duration when status changes or the server wait budget is exhausted.

### Get Findings

`GET /api/v1/investigations/{investigation_id}/findings`

Success returns `200 OK` and the findings response. A non-completed investigation returns `409 investigation_not_complete` with polling guidance.

### Health

`GET /health/live` reports process liveness and does not contact dependencies.

`GET /health/ready` verifies the registry and a bounded platform identity/connectivity operation. It returns `200` when ready and `503` when a required dependency is unavailable. Health responses never include secrets, tokens, internal URLs, or exception details.

## MCP Tool Contract

MCP exposes exactly three tools. Their semantic request, response, authorization, ownership, validation, and error behavior is identical to the HTTP domain contract.

### `create_platform_investigation`

Input fields:

- `description` (required string)
- `caller_label` (required string)
- `workload_name` (deprecated compatibility alias)
- `severity` (optional enum, default `medium`)
- `context` (optional string)
- `idempotency_key` (required string)

Successful tool content contains the canonical lifecycle response as structured content. During Azure SRE connector compatibility, the server may additionally provide the same object serialized as JSON text.

### `get_investigation_status`

Input fields:

- `investigation_id` (required UUID string)
- `wait_seconds` (optional bounded integer, default `0`)

Successful tool content contains the canonical lifecycle response.

### `get_investigation_summary`

The tool name remains unchanged in v1 for caller compatibility even though the canonical resource is named findings.

Input fields:

- `investigation_id` (required UUID string)

Successful tool content contains the canonical findings response.

### MCP Errors

Protocol errors use standard MCP/JSON-RPC error codes. Domain errors from an invoked tool use the same stable `code`, `detail`, `correlation_id`, `retryable`, and optional `retry_after_seconds` fields as HTTP problem details, represented as a tool error result according to the official MCP SDK.

Unknown methods and unknown tools must not expose implementation details. Authentication failures occur before domain dispatch.

## Compatibility and Deprecation

The following current HTTP routes remain as wrappers for one release after `/api/v1` becomes available:

| Deprecated route | v1 replacement |
|---|---|
| `POST /api/investigations` | `POST /api/v1/investigations` |
| `POST /api/investigations/status` | `GET /api/v1/investigations/{investigation_id}` |
| `POST /api/investigations/summary` | `GET /api/v1/investigations/{investigation_id}/findings` |

Compatibility wrappers retain their current request and response shapes but use the shared v1 authorization and domain implementation. They emit deprecation and sunset headers and are removed only in a documented breaking release.

The MCP tool names remain stable throughout v1. `workload_name` remains accepted as a deprecated alias for `caller_label` throughout v1 and is not used for authorization.

## Versioning Rules

- `schema_version` versions domain response bodies independently of MCP protocol and HTTP path versions.
- Additive optional fields are backward compatible within v1.
- New enum values, required fields, type changes, renamed fields, or removed fields require a new major contract.
- Problem `code` values are stable API surface.
- Generated OpenAPI, MCP tool schemas, examples, and contract tests must agree with this document.

## Security Invariants

Every implementation and transport must preserve these invariants:

1. The validated caller application ID controls registration, quota, idempotency scope, and ownership.
2. Caller labels and investigation evidence are always untrusted input.
3. Platform thread IDs, access tokens, credentials, signed URLs, and internal exception details are never public response fields.
4. Callers cannot list or discover another caller's investigations.
5. Both transports invoke the same domain service methods and return equivalent domain errors.
6. Findings are schema-validated and redacted before public return.
7. The proxy performs no remediation and exposes no general Platform SRE Agent administration operation.