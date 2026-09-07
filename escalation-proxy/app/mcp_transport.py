"""Official MCP Streamable HTTP transport for the escalation service."""

import os
from contextvars import ContextVar
from typing import Any

from fastapi import HTTPException
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_caller: ContextVar[Any] = ContextVar("mcp_caller", default=None)


class McpProbeAndTransport:
    def __init__(self, transport, server):
        self.transport = transport
        self.server = server

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] == "GET":
            body = b'{"status":"ok","protocol":"mcp","version":"2024-11-05"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.transport(scope, receive, send)


class CallerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in {"POST", "GET"}:
            authorization = request.headers.get("authorization")
            from main import extract_and_validate_token

            try:
                _token, caller = extract_and_validate_token(authorization)
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                )
            token = _caller.set(caller)
            try:
                return await call_next(request)
            finally:
                _caller.reset(token)
        return await call_next(request)


def _require_caller():
    caller = _caller.get()
    if caller is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return caller


def create_mcp_app():
    allowed_hosts = [
        value.strip()
        for value in os.environ.get(
            "MCP_ALLOWED_HOSTS",
            "127.0.0.1:*,localhost:*,testserver,testserver:*,",
        ).split(",")
        if value.strip()
    ]
    server = FastMCP(
        name="platform-escalation-proxy",
        instructions="Investigation-only access to the Platform SRE Agent.",
        streamable_http_path="/",
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=os.environ.get("MCP_ENABLE_DNS_REBINDING_PROTECTION", "true").lower()
            == "true",
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        ),
    )

    @server.tool()
    async def create_platform_investigation(
        description: str,
        workload_name: str,
        severity: str = "medium",
        context: str = "",
        idempotency_key: str = "",
    ) -> dict[str, Any]:
        """Create an investigation through the Platform Escalation Service."""
        from main import CreateInvestigationRequest, _create_investigation_impl

        return await _create_investigation_impl(
            CreateInvestigationRequest(
                description=description,
                workload_name=workload_name,
                severity=severity,
                context=context,
            ),
            _require_caller(),
            idempotency_key,
        )

    @server.tool()
    async def get_investigation_status(
        investigation_id: str,
        wait_seconds: int = 0,
    ) -> dict[str, Any]:
        """Get the status of a caller-owned investigation."""
        from main import GetInvestigationRequest, _get_status_impl

        return await _get_status_impl(
            GetInvestigationRequest(
                investigation_id=investigation_id,
                wait_seconds=wait_seconds,
            ),
            _require_caller(),
        )

    @server.tool()
    async def get_investigation_summary(investigation_id: str) -> dict[str, Any]:
        """Get redacted findings for a caller-owned investigation."""
        from main import GetInvestigationRequest, _get_summary_impl

        return await _get_summary_impl(
            GetInvestigationRequest(investigation_id=investigation_id),
            _require_caller(),
        )

    mcp_app = server.streamable_http_app()
    mcp_app.add_middleware(CallerAuthMiddleware)
    return McpProbeAndTransport(mcp_app, server)
