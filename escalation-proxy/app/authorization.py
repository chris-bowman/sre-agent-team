"""Caller token validation and operator-owned authorization policy wiring."""

from dataclasses import dataclass
from typing import Any, Callable

import jwt
from fastapi import HTTPException

from caller_policy import CallerPolicyStore, RefreshingCallerPolicyStore

ALLOWED_SEVERITY_LEVELS = {"low", "medium", "high", "critical"}
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class CallerIdentity:
    """Identity claims validated for an app-only escalation caller."""

    claims: dict[str, Any]

    @property
    def oid(self) -> str | None:
        return self.claims.get("oid")

    @property
    def appid(self) -> str | None:
        return self.claims.get("appid")

    @property
    def roles(self) -> list[str]:
        roles = self.claims.get("roles", [])
        return roles if isinstance(roles, list) else []


class CallerAuthorization:
    """Validate Entra caller tokens and request-level authorization claims."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        severity_claim: str,
        require_severity_claim: bool,
        event_sink: Callable[..., None],
        jwks_client: Any = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._severity_claim = severity_claim
        self._require_severity_claim = require_severity_claim
        self._event_sink = event_sink
        jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        self._jwks_client = jwks_client or jwt.PyJWKClient(jwks_uri, cache_keys=True)

    def validate_caller_token(self, bearer_token: str) -> dict[str, Any]:
        """Validate signature, tenant, audience, role, and app-only identity claims."""
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(bearer_token)
            payload = jwt.decode(
                bearer_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=[self._client_id, f"api://{self._client_id}"],
                issuer=f"https://sts.windows.net/{self._tenant_id}/",
            )
        except jwt.ExpiredSignatureError as exc:
            raise ValueError("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise ValueError(f"Invalid token: {exc}") from exc

        roles = payload.get("roles", [])
        if "EscalationCaller" not in roles:
            self._event_sink(
                "caller_token_missing_role",
                appid=payload.get("appid"),
                oid=payload.get("oid"),
                azp=payload.get("azp"),
                audience=payload.get("aud"),
                roles=roles if isinstance(roles, list) else [],
                issued_at=payload.get("iat"),
                expires_at=payload.get("exp"),
            )
            raise ValueError("Caller does not have the EscalationCaller app role")
        idtyp = payload.get("idtyp")
        if idtyp not in (None, "app") or "scp" in payload:
            raise ValueError("Caller token must represent an application identity")
        if not payload.get("appid"):
            raise ValueError("Token missing appid claim")
        if not payload.get("oid"):
            raise ValueError("Token missing oid claim")
        return payload

    def extract_and_validate_token(self, authorization: str | None = None) -> tuple[str, CallerIdentity]:
        """Extract a Bearer token and return its validated caller identity."""
        if not authorization:
            self._event_sink("caller_authorization_denied", outcome="denied", reason="missing_authorization_header")
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        if not authorization.startswith("Bearer "):
            self._event_sink("caller_authorization_denied", outcome="denied", reason="invalid_authorization_format")
            raise HTTPException(status_code=401, detail="Invalid Authorization header format")

        token = authorization.removeprefix("Bearer ").strip()
        try:
            payload = self.validate_caller_token(token)
        except ValueError as exc:
            self._event_sink("caller_authorization_denied", outcome="denied", reason="token_validation_failed")
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        caller = CallerIdentity(payload)
        self._event_sink(
            "caller_token_validated",
            outcome="authorized",
            appid=caller.appid,
            azp=payload.get("azp"),
            oid=caller.oid,
            roles=caller.roles,
        )
        return token, caller

    def validate_requested_severity(self, severity: str, claims: dict[str, Any]) -> str:
        """Validate severity syntax and enforce an optional token claim ceiling."""
        normalized = (severity or "").strip().lower()
        if normalized not in ALLOWED_SEVERITY_LEVELS:
            raise ValueError(f"severity must be one of {sorted(ALLOWED_SEVERITY_LEVELS)}")

        claim_value = claims.get(self._severity_claim)
        if claim_value is None:
            if self._require_severity_claim:
                raise ValueError(f"Token missing {self._severity_claim} claim")
            return normalized
        if not isinstance(claim_value, str) or claim_value.strip().lower() not in ALLOWED_SEVERITY_LEVELS:
            raise ValueError(f"Token claim {self._severity_claim} is invalid")

        maximum = claim_value.strip().lower()
        if SEVERITY_ORDER[normalized] > SEVERITY_ORDER[maximum]:
            raise ValueError(f"Requested severity exceeds token limit ({maximum})")
        return normalized


def build_caller_policy_store(
    app_configuration_endpoint: str,
    key: str,
    label: str,
    fallback_json: str,
    default_quota: int,
    refresh_interval_seconds: float,
    maximum_staleness_seconds: float,
    event_sink: Callable[..., None],
) -> CallerPolicyStore | RefreshingCallerPolicyStore:
    """Build the configured policy backend without exposing storage details to transports."""
    if app_configuration_endpoint:
        return RefreshingCallerPolicyStore(
            endpoint=app_configuration_endpoint,
            key=key,
            label=label,
            default_quota=default_quota,
            refresh_interval_seconds=refresh_interval_seconds,
            maximum_staleness_seconds=maximum_staleness_seconds,
            event_sink=event_sink,
        )
    return CallerPolicyStore.from_json(fallback_json, default_quota)
