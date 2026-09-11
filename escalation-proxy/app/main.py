"""
escalation-proxy/app/main.py

Platform Escalation HTTP Proxy
------------------------------
HTTP proxy that allows authorized callers to escalate platform-layer investigations
to the central Platform SRE Agent.

It exposes exactly 3 HTTP endpoints:
  - POST /api/investigations         - create_platform_investigation
  - POST /api/investigations/status  - get_investigation_status
  - POST /api/investigations/summary - get_investigation_summary

The proxy:
  1. Validates the caller's Entra ID token (must have 'EscalationCaller' app role).
  2. Calls the Platform SRE Agent REST API using its own managed identity (MSAL).
  3. Returns structured results — never exposing memories, config, or other agent data.

Environment variables (set in Container App):
  PLATFORM_AGENT_ENDPOINT   - e.g. https://sre-platform.abc123.azuresre.ai
  ENTRA_TENANT_ID           - Azure tenant ID
  ENTRA_CLIENT_ID           - This proxy's Entra app registration client ID
  AZURE_CLIENT_ID           - Container App managed identity client ID (for MSAL)
    REGISTRY_BACKEND           - 'memory' for local use or 'table' for Azure Tables
    REGISTRY_TABLE_ENDPOINT    - Azure Table service endpoint when backend is 'table'
    REGISTRY_TABLE_NAME        - Table name, default InvestigationRegistry
"""

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from authorization import CallerAuthorization, CallerIdentity, build_caller_policy_store
from contracts import (
    CreateInvestigationRequest,
    CreateInvestigationV1Request,
    GetInvestigationRequest,
    InvestigationFindingsResponse,
    InvestigationLifecycleResponse,
    RedactedSummaryResponse,
)
from investigation_registry import (
    ACTIVE_METADATA_RETENTION_SECONDS as ACTIVE_METADATA_RETENTION_SECONDS,
)
from investigation_registry import (
    FINAL_FINDINGS_METADATA_RETENTION_SECONDS as FINAL_FINDINGS_METADATA_RETENTION_SECONDS,
)
from investigation_registry import (
    MAX_EXPIRY_CLEANUP_BATCH_SIZE,
    MAX_INVESTIGATIONS_PER_WORKLOAD,
    MIN_STATUS_POLL_INTERVAL_SECONDS,
    InvestigationRecord,
    build_investigation_registry,
)
from investigation_registry import (
    MAX_STATUS_POLLS_PER_INVESTIGATION as MAX_STATUS_POLLS_PER_INVESTIGATION,
)
from investigation_registry import (
    InvestigationRegistry as InvestigationRegistry,
)
from investigation_registry import (
    TableStorageInvestigationRegistry as TableStorageInvestigationRegistry,
)
from investigation_service import InvestigationService, InvestigationServiceConfig
from output_validation import (
    is_finalized_summary as _output_is_finalized_summary,
)
from output_validation import normalize_status_value as _output_normalize_status_value
from output_validation import parse_finalized_findings as _output_parse_finalized_findings
from output_validation import redact_sensitive_text as _output_redact_sensitive_text
from output_validation import select_best_summary_text as _output_select_best_summary_text
from output_validation import summary_candidate_score as _output_summary_candidate_score
from platform_client import (
    PlatformCircuitBreaker as PlatformCircuitBreaker,
)
from platform_client import (
    _platform_circuit_breaker as _platform_circuit_breaker,
)
from platform_client import (
    _platform_request as _platform_request,
)
from platform_client import (
    get_platform_agent_token as get_platform_agent_token,
)
from telemetry import log_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

# Keep third-party libraries quiet so proxy lifecycle logs are easy to read.
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)

# ── Configuration ────────────────────────────────────────────────────────────
PLATFORM_AGENT_ENDPOINT = os.environ["PLATFORM_AGENT_ENDPOINT"].rstrip("/")
ENTRA_TENANT_ID = os.environ["ENTRA_TENANT_ID"]
ENTRA_CLIENT_ID = os.environ["ENTRA_CLIENT_ID"]  # This app's client ID

PLATFORM_AGENT_V2_API = f"{PLATFORM_AGENT_ENDPOINT}/api/v2"
FINALIZATION_TOKEN = os.environ.get("FINALIZATION_TOKEN", "ESCALATION_FINAL_V1")
REQUIRE_FINALIZATION_TOKEN = os.environ.get("REQUIRE_FINALIZATION_TOKEN", "true").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
TARGET_LIAISON_AGENT = os.environ.get("TARGET_LIAISON_AGENT", "workload_liaison")
CALLER_POLICIES_JSON = os.environ.get("CALLER_POLICIES_JSON", "")
APP_CONFIG_ENDPOINT = os.environ.get("APP_CONFIG_ENDPOINT", "").rstrip("/")
CALLER_POLICY_KEY = os.environ.get("CALLER_POLICY_KEY", "escalation/caller-policies")
CALLER_POLICY_LABEL = os.environ.get("CALLER_POLICY_LABEL", "production")
CALLER_POLICY_REFRESH_SECONDS = max(float(os.environ.get("CALLER_POLICY_REFRESH_SECONDS", "30")), 1.0)
CALLER_POLICY_MAX_STALENESS_SECONDS = max(
    float(os.environ.get("CALLER_POLICY_MAX_STALENESS_SECONDS", "300")),
    CALLER_POLICY_REFRESH_SECONDS,
)

# ── Resource Limits and Quotas ───────────────────────────────────────────────
MAX_INVESTIGATION_DESCRIPTION_SIZE = 5000  # characters
MAX_INVESTIGATION_CONTEXT_SIZE = 10000  # characters
MAX_WORKLOAD_NAME_SIZE = 256  # characters
MAX_IDEMPOTENCY_KEY_SIZE = 128
MAX_REQUEST_BODY_BYTES = max(int(os.environ.get("MAX_REQUEST_BODY_BYTES", "65536")), 16384)
EXPIRY_CLEANUP_INTERVAL_SECONDS = max(float(os.environ.get("EXPIRY_CLEANUP_INTERVAL_SECONDS", "300")), 1.0)
# Long-polling: a single get_investigation_status call can block server-side and
# Long-polling: a single get_investigation_status call can block server-side and
# recheck the platform thread internally, so the calling agent rarely needs a
# separate turn per check. The SRE Agent's own tool-call timeout is 2 minutes
# (120s) and Container Apps ingress hard-times-out at 240s — 120s is the
# binding constraint, so stay safely under it. Hard-clamped so misconfiguration
# via env var can't push this past a safe margin.
MAX_STATUS_WAIT_SECONDS = min(int(os.environ.get("MAX_STATUS_WAIT_SECONDS", "90")), 100)
STATUS_POLL_INTERVAL_SECONDS = int(os.environ.get("STATUS_POLL_INTERVAL_SECONDS", "5"))
ALLOWED_SEVERITY_LEVELS = {"low", "medium", "high", "critical"}
SEVERITY_CLAIM = os.environ.get("SEVERITY_CLAIM", "max_escalation_severity")
REQUIRE_SEVERITY_CLAIM = os.environ.get("REQUIRE_SEVERITY_CLAIM", "false").strip().lower() in ("1", "true", "yes", "on")

_investigation_registry = build_investigation_registry()
_caller_policy_store = build_caller_policy_store(
    app_configuration_endpoint=APP_CONFIG_ENDPOINT,
    key=CALLER_POLICY_KEY,
    label=CALLER_POLICY_LABEL,
    fallback_json=CALLER_POLICIES_JSON,
    default_quota=MAX_INVESTIGATIONS_PER_WORKLOAD,
    refresh_interval_seconds=CALLER_POLICY_REFRESH_SECONDS,
    maximum_staleness_seconds=CALLER_POLICY_MAX_STALENESS_SECONDS,
    event_sink=log_event,
)
_caller_authorization = CallerAuthorization(
    tenant_id=ENTRA_TENANT_ID,
    client_id=ENTRA_CLIENT_ID,
    severity_claim=SEVERITY_CLAIM,
    require_severity_claim=REQUIRE_SEVERITY_CLAIM,
    event_sink=log_event,
)
validate_caller_token = _caller_authorization.validate_caller_token
validate_requested_severity = _caller_authorization.validate_requested_severity
extract_and_validate_token = _caller_authorization.extract_and_validate_token


class RequestBodyLimitMiddleware:
    def __init__(self, app, maximum_bytes: int) -> None:
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        content_length = next((value for name, value in scope["headers"] if name == b"content-length"), None)
        if content_length is not None and int(content_length) > self.maximum_bytes:
            await JSONResponse(status_code=413, content={"detail": "Request body is too large"})(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.maximum_bytes:
                await JSONResponse(status_code=413, content={"detail": "Request body is too large"})(
                    scope, receive, send
                )
                return
            if not message.get("more_body", False):
                break

        body_sent = False

        async def receive_buffered_body():
            nonlocal body_sent
            if body_sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            body_sent = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, receive_buffered_body, send)


def redact_sensitive_text(text: str) -> str:
    """Remove credential-shaped values before returning platform output."""
    return _output_redact_sensitive_text(text, event_sink=log_event)


# ── HTTP API Server ──────────────────────────────────────────────────────────
app = FastAPI(title="Platform Escalation Proxy")
app.add_middleware(RequestBodyLimitMiddleware, maximum_bytes=MAX_REQUEST_BODY_BYTES)

MCP_SERVER_INFO = {"name": "platform-escalation-proxy", "version": "1.0.0"}
MCP_PROTOCOL_VERSION = "2024-11-05"

_V1_PROBLEM_CODES = {
    400: ("invalid_request", "Invalid request", False),
    401: ("authentication_required", "Authentication required", False),
    403: ("caller_not_authorized", "Caller is not authorized", False),
    404: ("investigation_not_found", "Investigation not found", False),
    409: ("conflict", "Request conflicts with current investigation state", False),
    429: ("quota_exceeded", "Request limit exceeded", True),
    502: ("invalid_platform_response", "Platform response was invalid", False),
    503: ("platform_unavailable", "Platform service is temporarily unavailable", True),
}


@app.exception_handler(HTTPException)
async def versioned_problem_details(request: Request, exc: HTTPException):
    """Return stable problem details for the public versioned HTTP contract."""
    if not request.url.path.startswith("/api/v1/"):
        headers = {}
        legacy_successors = {
            "/api/investigations": "/api/v1/investigations",
            "/api/investigations/status": "/api/v1/investigations/{investigation_id}",
            "/api/investigations/summary": "/api/v1/investigations/{investigation_id}/findings",
        }
        successor = legacy_successors.get(request.url.path)
        if successor:
            headers = {
                "Deprecation": "true",
                "Link": f'<{successor}>; rel="successor-version"',
            }
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=headers)

    code, title, retryable = _V1_PROBLEM_CODES.get(exc.status_code, ("internal_error", "Service request failed", False))
    return JSONResponse(
        status_code=exc.status_code,
        media_type="application/problem+json",
        content={
            "type": f"https://github.com/microsoft/sre-agent-team/problems/{code}",
            "title": title,
            "status": exc.status_code,
            "code": code,
            "detail": title,
            "correlation_id": str(uuid.uuid4()),
            "retryable": retryable,
        },
    )


class McpRequest(BaseModel):
    jsonrpc: str
    id: Any = None
    method: str
    params: dict[str, Any] = {}


def _mcp_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _mcp_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def _mcp_tools_list() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": "create_platform_investigation",
                "description": "Create a platform investigation thread.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "description": {"type": "string"},
                        "workload_name": {"type": "string"},
                        "severity": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                        },
                        "context": {"type": "string"},
                    },
                    "required": ["description", "workload_name"],
                },
            },
            {
                "name": "get_investigation_status",
                "description": (
                    "Get investigation status by investigation_id. Optionally long-polls: "
                    "pass wait_seconds to block server-side (capped, see response) and recheck "
                    "internally instead of needing a separate call every few minutes."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "investigation_id": {"type": "string"},
                        "wait_seconds": {
                            "type": "integer",
                            "description": f"Seconds to long-poll before returning (capped at {MAX_STATUS_WAIT_SECONDS}). Default 0 (return immediately).",
                        },
                    },
                    "required": ["investigation_id"],
                },
            },
            {
                "name": "get_investigation_summary",
                "description": "Get final investigation summary by investigation_id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "investigation_id": {"type": "string"},
                    },
                    "required": ["investigation_id"],
                },
            },
        ]
    }


def _normalize_status_value(value: Any) -> str:
    return _output_normalize_status_value(value)


def _summary_candidate_score(text: str) -> int:
    return _output_summary_candidate_score(text, finalization_token=FINALIZATION_TOKEN)


def _select_best_summary_text(agent_texts: list[str]) -> tuple[int, str, str]:
    return _output_select_best_summary_text(agent_texts, finalization_token=FINALIZATION_TOKEN)


def _is_finalized_summary(best_score: int, selected_text: str) -> bool:
    return _output_is_finalized_summary(
        best_score,
        selected_text,
        require_finalization_token=REQUIRE_FINALIZATION_TOKEN,
        finalization_token=FINALIZATION_TOKEN,
    )


def _parse_finalized_findings(report: str) -> dict[str, Any] | None:
    """Parse the liaison's final Markdown report into the public allowlisted schema."""
    return _output_parse_finalized_findings(report, finalization_token=FINALIZATION_TOKEN)


def _build_investigation_service(
    *,
    fetch_status_once=None,
) -> InvestigationService:
    """Build a service from current module globals so compatibility patches remain effective."""
    return InvestigationService(
        config=InvestigationServiceConfig(
            max_description_size=MAX_INVESTIGATION_DESCRIPTION_SIZE,
            max_context_size=MAX_INVESTIGATION_CONTEXT_SIZE,
            max_workload_name_size=MAX_WORKLOAD_NAME_SIZE,
            max_idempotency_key_size=MAX_IDEMPOTENCY_KEY_SIZE,
            max_status_wait_seconds=MAX_STATUS_WAIT_SECONDS,
            status_poll_interval_seconds=STATUS_POLL_INTERVAL_SECONDS,
            min_status_poll_interval_seconds=MIN_STATUS_POLL_INTERVAL_SECONDS,
            target_liaison_agent=TARGET_LIAISON_AGENT,
            finalization_token=FINALIZATION_TOKEN,
            require_finalization_token=REQUIRE_FINALIZATION_TOKEN,
        ),
        registry=_investigation_registry,
        caller_policy_store=_caller_policy_store,
        validate_requested_severity=validate_requested_severity,
        get_platform_agent_token=get_platform_agent_token,
        platform_request=_platform_request,
        normalize_status_value=_normalize_status_value,
        select_best_summary_text=_select_best_summary_text,
        is_finalized_summary=_is_finalized_summary,
        parse_finalized_findings=_parse_finalized_findings,
        redact_sensitive_text=redact_sensitive_text,
        event_sink=log_event,
        sleep=asyncio.sleep,
        monotonic=time.monotonic,
        wall_time=time.time,
        uuid_factory=uuid.uuid4,
        fetch_status_once=fetch_status_once,
    )


async def _create_investigation_impl(
    req: CreateInvestigationRequest, caller: CallerIdentity, idempotency_key: str = ""
) -> dict[str, Any]:
    return await _build_investigation_service().create_investigation(req, caller, idempotency_key)


async def _fetch_investigation_status_once(record: InvestigationRecord) -> str:
    """Check the platform thread once and return a normalized status string."""
    return await _build_investigation_service().fetch_investigation_status_once(record)


async def _get_status_impl(req: GetInvestigationRequest, caller: CallerIdentity) -> dict[str, Any]:
    return await _build_investigation_service(fetch_status_once=_fetch_investigation_status_once).get_status(
        req, caller
    )


async def _get_summary_impl(req: GetInvestigationRequest, caller: CallerIdentity) -> dict[str, Any]:
    return await _build_investigation_service().get_summary(req, caller)


def _v1_lifecycle_response(
    investigation_id: str, status: str, caller: CallerIdentity
) -> InvestigationLifecycleResponse:
    """Build the canonical lifecycle response from caller-owned registry data."""
    return _build_investigation_service().v1_lifecycle_response(investigation_id, status, caller)


def _v1_findings_response(
    investigation_id: str, result: dict[str, Any], caller: CallerIdentity
) -> InvestigationFindingsResponse:
    return _build_investigation_service().v1_findings_response(investigation_id, result, caller)


# ── HTTP Endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root_check():
    return {"status": "healthy"}


@app.get("/health/live")
async def liveness_check():
    """Report process liveness without contacting external dependencies."""
    return {"status": "healthy"}


@app.get("/health")
async def health_check():
    """Backward-compatible alias for the liveness probe."""
    return await liveness_check()


@app.get("/health/ready")
async def readiness_check():
    """Report whether required policy, registry, and platform dependencies are usable."""
    try:
        _caller_policy_store.health_check()
    except Exception:
        log_event("readiness_check_failed", dependency="caller_policy")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    try:
        _investigation_registry.health_check()
    except Exception:
        log_event("readiness_check_failed", dependency="registry")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    try:
        get_platform_agent_token()
    except Exception:
        log_event("readiness_check_failed", dependency="platform_identity")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    if not _platform_circuit_breaker.is_available():
        log_event("readiness_check_failed", dependency="platform_circuit")
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    log_event("readiness_check_succeeded", outcome="success")
    return {"status": "ready"}


@app.get("/mcp-probe")
async def mcp_probe():
    # The SRE Agent connector probes this path before starting MCP calls.
    return {"status": "ok", "protocol": "mcp", "version": MCP_PROTOCOL_VERSION}


@app.post("/mcp-legacy")
async def mcp_handler(body: McpRequest, authorization: str = Header(None)):
    try:
        log_event("mcp_request_received", method=body.method, request_id=body.id)
        requires_auth = body.method == "tools/call"
        caller = None
        if requires_auth:
            _token, caller = extract_and_validate_token(authorization)

        if body.method == "initialize":
            return _mcp_result(
                body.id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": MCP_SERVER_INFO,
                },
            )

        if body.method == "notifications/initialized":
            return _mcp_result(body.id, {})

        if body.method == "ping":
            # SRE Agent uses ping heartbeats to keep MCP connectors healthy.
            return _mcp_result(body.id, {})

        if body.method == "tools/list":
            return _mcp_result(body.id, _mcp_tools_list())

        if body.method == "tools/call":
            name = (body.params or {}).get("name", "")
            args = (body.params or {}).get("arguments") or {}
            log_event("mcp_tool_call_started", request_id=body.id, tool_name=name)

            if name == "create_platform_investigation":
                result = await _create_investigation_impl(CreateInvestigationRequest(**args), caller)
            elif name == "get_investigation_status":
                result = await _get_status_impl(GetInvestigationRequest(**args), caller)
            elif name == "get_investigation_summary":
                result = await _get_summary_impl(GetInvestigationRequest(**args), caller)
            else:
                return _mcp_error(body.id, -32601, f"Unknown tool: {name}")

            log_event("mcp_tool_call_completed", request_id=body.id, tool_name=name)

            return _mcp_result(body.id, {"content": [{"type": "text", "text": json.dumps(result)}]})

        return _mcp_error(body.id, -32601, f"Method not found: {body.method}")
    except HTTPException as ex:
        log_event(
            "mcp_http_exception", method=body.method, request_id=body.id, status_code=ex.status_code, detail=ex.detail
        )
        return _mcp_error(body.id, -32001, ex.detail)
    except Exception as ex:
        logger.exception("MCP handler error")
        log_event("mcp_unhandled_exception", method=body.method, request_id=body.id, error=str(ex))
        return _mcp_error(body.id, -32000, "Internal server error")


from mcp_transport import create_mcp_app  # noqa: E402

mcp_transport = create_mcp_app()
app.mount("/mcp", mcp_transport)


async def _run_expiry_cleanup() -> None:
    while True:
        try:
            count = await asyncio.to_thread(
                _investigation_registry.cleanup_expired,
                MAX_EXPIRY_CLEANUP_BATCH_SIZE,
            )
            if count > 0:
                log_event("expiry_cleanup_completed", count=count)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Investigation registry cleanup failed")
            log_event("expiry_cleanup_failed", error_type=type(exc).__name__)
        await asyncio.sleep(EXPIRY_CLEANUP_INTERVAL_SECONDS)


@asynccontextmanager
async def mcp_lifespan(_application):
    cleanup_task = asyncio.create_task(_run_expiry_cleanup())
    try:
        async with mcp_transport.server.session_manager.run():
            yield
    finally:
        cleanup_task.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup_task


app.router.lifespan_context = mcp_lifespan


@app.post("/api/investigations")
async def create_investigation(
    req: CreateInvestigationRequest,
    response: Response,
    authorization: str = Header(None),
):
    """
    Create a platform investigation through the legacy compatibility route.

    Args:
        description:   Clear description of the problem.
        workload_name: Deprecated display label for the caller; retained for v1 compatibility.
        severity:      'low' | 'medium' | 'high' | 'critical'
        context:       Additional diagnostic context.

    Returns:
        investigation_id: Use this to poll status and retrieve results.
        status:           Initial status ('pending').
    """
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</api/v1/investigations>; rel="successor-version"'
    _token, caller = extract_and_validate_token(authorization)
    return await _create_investigation_impl(req, caller)


@app.post("/api/v1/investigations", response_model=InvestigationLifecycleResponse, status_code=202)
async def create_investigation_v1(
    req: CreateInvestigationV1Request,
    authorization: str = Header(None),
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
):
    """Create an investigation using the versioned HTTP contract."""
    _token, caller = extract_and_validate_token(authorization)
    legacy_request = CreateInvestigationRequest(
        description=req.description,
        workload_name=req.caller_label,
        severity=req.severity,
        context=req.context,
    )
    result = await _create_investigation_impl(legacy_request, caller, idempotency_key)
    response = _v1_lifecycle_response(result["investigation_id"], result["status"], caller)
    return response


@app.post("/api/investigations/status")
async def get_status(
    req: GetInvestigationRequest,
    response: Response,
    authorization: str = Header(None),
):
    """
    Check the current status of a platform investigation.

    Args:
        investigation_id: The ID returned by create_investigation.
        wait_seconds: Optional. Long-poll up to this many seconds (capped at
            MAX_STATUS_WAIT_SECONDS) instead of returning immediately, so a
            single call can wait out most investigations without needing a
            separate call every few minutes.

    Returns:
        status:   'pending' | 'running' | 'completed' | 'failed'
        progress: Human-readable progress description.
    """
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</api/v1/investigations/{investigation_id}>; rel="successor-version"'
    _token, caller = extract_and_validate_token(authorization)
    return await _get_status_impl(req, caller)


@app.get("/api/v1/investigations/{investigation_id}", response_model=InvestigationLifecycleResponse)
async def get_investigation_v1(
    investigation_id: str,
    wait_seconds: int = 0,
    authorization: str = Header(None),
):
    """Get an investigation lifecycle state using the versioned HTTP contract."""
    _token, caller = extract_and_validate_token(authorization)
    result = await _get_status_impl(
        GetInvestigationRequest(investigation_id=investigation_id, wait_seconds=wait_seconds),
        caller,
    )
    return _v1_lifecycle_response(investigation_id, result["status"], caller)


@app.get(
    "/api/v1/investigations/{investigation_id}/findings",
    response_model=InvestigationFindingsResponse,
)
async def get_investigation_findings_v1(
    investigation_id: str,
    authorization: str = Header(None),
):
    """Get validated findings for a completed investigation."""
    _token, caller = extract_and_validate_token(authorization)
    result = await _get_summary_impl(GetInvestigationRequest(investigation_id=investigation_id), caller)
    return _v1_findings_response(investigation_id, result, caller)


@app.post("/api/investigations/summary", response_model=RedactedSummaryResponse)
async def get_summary(
    req: GetInvestigationRequest,
    response: Response,
    authorization: str = Header(None),
):
    """
    Retrieve the final findings of a completed platform investigation.
    Call get_status first and only call this when status is 'completed'.

    Args:
        investigation_id: The ID returned by create_investigation.

    Returns:
        summary:   Structured findings from the Platform SRE Agent.
        status:    Should be 'completed' — if not, poll status again.
    """
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</api/v1/investigations/{investigation_id}/findings>; rel="successor-version"'
    _token, caller = extract_and_validate_token(authorization)
    return await _get_summary_impl(req, caller)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)  # nosec B104
