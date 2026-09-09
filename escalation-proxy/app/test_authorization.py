from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from authorization import CallerAuthorization, CallerPolicyStore, build_caller_policy_store


@pytest.fixture
def authorization():
    return CallerAuthorization(
        tenant_id="tenant-id",
        client_id="client-id",
        severity_claim="max_escalation_severity",
        require_severity_claim=False,
        event_sink=MagicMock(),
        jwks_client=MagicMock(get_signing_key_from_jwt=MagicMock(return_value=SimpleNamespace(key="key"))),
    )


def test_validates_signature_tenant_audience_and_app_identity(authorization):
    payload = {
        "appid": "caller-app-id",
        "oid": "caller-object-id",
        "idtyp": "app",
        "roles": ["EscalationCaller"],
    }

    with patch("authorization.jwt.decode", return_value=payload) as decode:
        assert authorization.validate_caller_token("token") == payload

    decode.assert_called_once_with(
        "token",
        "key",
        algorithms=["RS256"],
        audience=["client-id", "api://client-id"],
        issuer="https://sts.windows.net/tenant-id/",
    )


def test_accepts_app_only_managed_identity_token_without_idtyp(authorization):
    payload = {
        "appid": "caller-app-id",
        "oid": "caller-object-id",
        "roles": ["EscalationCaller"],
    }

    with patch("authorization.jwt.decode", return_value=payload):
        assert authorization.validate_caller_token("token") == payload


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"appid": "app", "oid": "oid", "idtyp": "app", "roles": []}, "EscalationCaller"),
        (
            {"appid": "app", "oid": "oid", "idtyp": "user", "roles": ["EscalationCaller"]},
            "application identity",
        ),
        (
            {"appid": "app", "oid": "oid", "scp": "user.read", "roles": ["EscalationCaller"]},
            "application identity",
        ),
        ({"oid": "oid", "idtyp": "app", "roles": ["EscalationCaller"]}, "appid"),
        ({"appid": "app", "idtyp": "app", "roles": ["EscalationCaller"]}, "oid"),
    ],
)
def test_rejects_invalid_caller_shape(authorization, payload, message):
    with patch("authorization.jwt.decode", return_value=payload):
        with pytest.raises(ValueError, match=message):
            authorization.validate_caller_token("token")


def test_extract_maps_token_validation_failure_to_forbidden(authorization):
    with patch.object(authorization, "validate_caller_token", side_effect=ValueError("invalid token")):
        with pytest.raises(HTTPException) as error:
            authorization.extract_and_validate_token("Bearer token")

    assert error.value.status_code == 403
    assert error.value.detail == "invalid token"


def test_policy_factory_uses_local_json_fallback():
    store = build_caller_policy_store(
        app_configuration_endpoint="",
        key="key",
        label="production",
        fallback_json='[{"appid":"app","maximum_severity":"high"}]',
        default_quota=3,
        refresh_interval_seconds=30,
        maximum_staleness_seconds=300,
        event_sink=MagicMock(),
    )

    assert isinstance(store, CallerPolicyStore)
    assert store.authorize("app", "high").maximum_concurrent_investigations == 3
