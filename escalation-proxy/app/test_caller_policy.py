"""Tests for operator-owned caller policy enforcement."""

import pytest

from caller_policy import CallerPolicyStore


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
