"""Tests for operator-owned caller policy enforcement."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from caller_policy import CallerPolicyStore, RefreshingCallerPolicyStore


def test_registered_caller_policy_enforces_severity_and_quota():
    store = CallerPolicyStore.from_json(
        '[{"appid":"caller-a","display_name":"Caller A","enabled":true,'
        '"maximum_severity":"high","maximum_concurrent_investigations":2}]',
        default_quota=10,
    )

    policy = store.authorize("caller-a", "high")

    assert policy.display_name == "Caller A"
    assert policy.maximum_concurrent_investigations == 2
    with pytest.raises(ValueError, match="caller policy limit"):
        store.authorize("caller-a", "critical")


def test_refreshing_policy_store_uses_last_known_good_within_staleness_window():
    clock = MagicMock(side_effect=[10.0, 20.0])
    client = MagicMock()
    client.get_configuration_setting.side_effect = [
        SimpleNamespace(
            value='[{"appid":"caller","enabled":true,"maximum_severity":"high"}]',
            etag="one",
        ),
        RuntimeError("unavailable"),
    ]
    events = MagicMock()
    store = RefreshingCallerPolicyStore(
        endpoint="https://config.example",
        key="policy",
        label="production",
        default_quota=2,
        refresh_interval_seconds=1,
        maximum_staleness_seconds=30,
        event_sink=events,
        client=client,
        clock=clock,
    )

    assert store.authorize("caller", "high").maximum_concurrent_investigations == 2
    events.assert_any_call(
        "caller_policy_refresh_failed",
        source="app_configuration",
        using_last_known_good=True,
        error_type="RuntimeError",
    )


def test_refreshing_policy_store_fails_closed_after_maximum_staleness():
    clock = MagicMock(side_effect=[10.0, 50.0])
    client = MagicMock()
    client.get_configuration_setting.side_effect = [
        SimpleNamespace(value='[{"appid":"caller","enabled":true}]', etag="one"),
        RuntimeError("unavailable"),
    ]
    store = RefreshingCallerPolicyStore(
        endpoint="https://config.example",
        key="policy",
        label="production",
        default_quota=2,
        refresh_interval_seconds=1,
        maximum_staleness_seconds=30,
        event_sink=MagicMock(),
        client=client,
        clock=clock,
    )

    with pytest.raises(ValueError, match="Caller policy is unavailable"):
        store.authorize("caller", "high")


def test_configured_policy_rejects_disabled_and_unregistered_callers():
    store = CallerPolicyStore.from_json(
        '[{"appid":"caller-disabled","enabled":false,"maximum_concurrent_investigations":1}]',
        default_quota=10,
    )

    with pytest.raises(ValueError, match="disabled"):
        store.authorize("caller-disabled", "low")
    with pytest.raises(ValueError, match="not registered"):
        store.authorize("caller-unknown", "low")


def test_empty_policy_configuration_preserves_local_development_behavior():
    store = CallerPolicyStore.from_json("", default_quota=7)

    policy = store.authorize("local-caller", "critical")

    assert policy.enabled
    assert policy.maximum_concurrent_investigations == 7


def test_empty_dynamic_policy_fails_closed():
    client = MagicMock()
    client.get_configuration_setting.return_value = SimpleNamespace(value="[]", etag="one")
    store = RefreshingCallerPolicyStore(
        endpoint="https://config.example",
        key="policy",
        label="production",
        default_quota=2,
        refresh_interval_seconds=30,
        maximum_staleness_seconds=300,
        event_sink=MagicMock(),
        client=client,
        clock=MagicMock(return_value=10.0),
    )

    with pytest.raises(ValueError, match="not registered"):
        store.authorize("caller", "low")


def test_dynamic_policy_startup_failure_does_not_crash_and_fails_closed():
    client = MagicMock()
    client.get_configuration_setting.side_effect = RuntimeError("RBAC is still propagating")
    store = RefreshingCallerPolicyStore(
        endpoint="https://config.example",
        key="policy",
        label="production",
        default_quota=2,
        refresh_interval_seconds=30,
        maximum_staleness_seconds=300,
        event_sink=MagicMock(),
        client=client,
        clock=MagicMock(side_effect=[10.0, 11.0, 12.0]),
    )

    with pytest.raises(ValueError, match="Caller policy is unavailable"):
        store.authorize("caller", "low")

    with pytest.raises(ValueError, match="Caller policy is unavailable"):
        store.health_check()


def test_dynamic_policy_health_accepts_last_known_good_snapshot():
    client = MagicMock()
    client.get_configuration_setting.side_effect = [
        SimpleNamespace(value='[{"appid":"caller","enabled":true}]', etag="one"),
        RuntimeError("temporarily unavailable"),
    ]
    store = RefreshingCallerPolicyStore(
        endpoint="https://config.example",
        key="policy",
        label="production",
        default_quota=2,
        refresh_interval_seconds=30,
        maximum_staleness_seconds=300,
        event_sink=MagicMock(),
        client=client,
        clock=MagicMock(side_effect=[10.0, 20.0]),
    )

    store.health_check()
