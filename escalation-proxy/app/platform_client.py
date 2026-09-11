import asyncio
import os
import random
import time
from threading import Lock
from typing import Any

import httpx
from azure.core.credentials import AccessToken
from azure.identity import ManagedIdentityCredential
from fastapi import HTTPException

from telemetry import log_event

PLATFORM_AGENT_ENDPOINT = os.environ["PLATFORM_AGENT_ENDPOINT"].rstrip("/")
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
SRE_AGENT_SCOPE = os.environ.get("SRE_AGENT_SCOPE", "https://azuresre.dev/.default")
PLATFORM_AGENT_V1_API = f"{PLATFORM_AGENT_ENDPOINT}/api/v1"
PLATFORM_REQUEST_TIMEOUT_SECONDS = float(os.environ.get("PLATFORM_REQUEST_TIMEOUT_SECONDS", "30"))
PLATFORM_REQUEST_MAX_ATTEMPTS = int(os.environ.get("PLATFORM_REQUEST_MAX_ATTEMPTS", "3"))
PLATFORM_CIRCUIT_FAILURE_THRESHOLD = max(int(os.environ.get("PLATFORM_CIRCUIT_FAILURE_THRESHOLD", "5")), 1)
PLATFORM_CIRCUIT_RECOVERY_SECONDS = max(float(os.environ.get("PLATFORM_CIRCUIT_RECOVERY_SECONDS", "30")), 1.0)

mi_credential = ManagedIdentityCredential(client_id=AZURE_CLIENT_ID)


class PlatformCircuitBreaker:
    def __init__(self, failure_threshold: int, recovery_seconds: float) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_seconds = recovery_seconds
        self._failure_count = 0
        self._opened_at: float | None = None
        self._probe_in_flight = False
        self._lock = Lock()

    def before_request(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if time.monotonic() - self._opened_at < self.recovery_seconds or self._probe_in_flight:
                raise HTTPException(status_code=503, detail="Platform SRE Agent is temporarily unavailable")
            self._probe_in_flight = True

    def is_available(self) -> bool:
        with self._lock:
            return self._opened_at is None and not self._probe_in_flight

    def record_success(self) -> None:
        with self._lock:
            was_open = self._opened_at is not None
            self._failure_count = 0
            self._opened_at = None
            self._probe_in_flight = False
        if was_open:
            log_event("platform_circuit_closed")

    def record_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            self._failure_count += 1
            should_open = self._failure_count >= self.failure_threshold
            was_open = self._opened_at is not None
            if should_open:
                self._opened_at = time.monotonic()
        if should_open and not was_open:
            log_event("platform_circuit_opened", failure_threshold=self.failure_threshold)


_platform_circuit_breaker = PlatformCircuitBreaker(
    PLATFORM_CIRCUIT_FAILURE_THRESHOLD,
    PLATFORM_CIRCUIT_RECOVERY_SECONDS,
)


def _telemetry_path(path: str) -> str:
    if path == "/threads":
        return path
    if path.endswith("/messages"):
        return "/threads/{thread_id}/messages"
    if path.startswith("/threads/"):
        return "/threads/{thread_id}"
    return "/unknown"


def get_platform_agent_token() -> str:
    """Acquire a token for the platform SRE agent using managed identity."""
    token: AccessToken = mi_credential.get_token(SRE_AGENT_SCOPE)
    return token.token


async def _platform_request(method: str, path: str, token: str, **kwargs: Any) -> httpx.Response:
    """Call the Platform SRE Agent with bounded retries for transient failures."""
    _platform_circuit_breaker.before_request()
    started_at = time.monotonic()
    retryable_statuses = {429, 500, 502, 503, 504}
    retryable_method = method.upper() in {"GET", "HEAD", "OPTIONS"}
    last_error: Exception | None = None
    for attempt in range(PLATFORM_REQUEST_MAX_ATTEMPTS):
        try:
            async with httpx.AsyncClient(timeout=PLATFORM_REQUEST_TIMEOUT_SECONDS) as client:
                request_method = getattr(client, method.lower())
                response = await request_method(
                    f"{PLATFORM_AGENT_V1_API}{path}",
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    **kwargs,
                )
            if response.status_code not in retryable_statuses:
                response.raise_for_status()
                _platform_circuit_breaker.record_success()
                log_event(
                    "platform_request_completed",
                    outcome="success",
                    method=method,
                    path=_telemetry_path(path),
                    status_code=response.status_code,
                    attempts=attempt + 1,
                    duration_ms=round((time.monotonic() - started_at) * 1000),
                )
                return response
            last_error = httpx.HTTPStatusError(
                "Transient platform response", request=response.request, response=response
            )
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
            last_error = exc

        if retryable_method and attempt + 1 < PLATFORM_REQUEST_MAX_ATTEMPTS:
            await asyncio.sleep((0.25 * (2**attempt)) + random.uniform(0, 0.1))
            continue
        break

    _platform_circuit_breaker.record_failure()
    log_event(
        "platform_request_failed",
        outcome="failure",
        method=method,
        path=_telemetry_path(path),
        attempts=PLATFORM_REQUEST_MAX_ATTEMPTS,
        duration_ms=round((time.monotonic() - started_at) * 1000),
    )
    raise HTTPException(status_code=503, detail="Platform SRE Agent is temporarily unavailable") from last_error
