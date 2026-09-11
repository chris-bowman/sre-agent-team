"""Operator-owned authorization policy for same-tenant escalation callers."""

import json
import re
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable

from azure.appconfiguration import AzureAppConfigurationClient
from azure.identity import DefaultAzureCredential

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RESOURCE_GROUP_ID_PATTERN = re.compile(
    r"^/subscriptions/[0-9a-f-]{36}/resourcegroups/[a-z0-9._()\-]{1,90}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CallerPolicy:
    appid: str
    display_name: str
    enabled: bool
    maximum_severity: str
    maximum_concurrent_investigations: int
    allowed_resource_groups: frozenset[str]


class CallerPolicyStore:
    def __init__(
        self,
        policies: dict[str, CallerPolicy],
        default_quota: int,
        allow_unregistered: bool = True,
    ):
        self._policies = policies
        self._default_quota = default_quota
        self._allow_unregistered = allow_unregistered

    @classmethod
    def from_json(
        cls,
        raw: str,
        default_quota: int,
        allow_unregistered: bool = True,
    ) -> "CallerPolicyStore":
        if not raw.strip():
            return cls({}, default_quota, allow_unregistered)

        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            raise ValueError("CALLER_POLICIES_JSON must be a JSON array")

        policies = {}
        for entry in parsed:
            appid = str(entry["appid"]).strip()
            maximum_severity = str(entry.get("maximum_severity", "critical")).strip().lower()
            quota = int(entry.get("maximum_concurrent_investigations", default_quota))
            resource_groups = entry.get("allowed_resource_groups", [])
            if (
                not appid
                or maximum_severity not in SEVERITY_ORDER
                or quota < 1
                or not isinstance(resource_groups, list)
                or any(
                    not isinstance(group, str) or not RESOURCE_GROUP_ID_PATTERN.fullmatch(group.strip())
                    for group in resource_groups
                )
            ):
                raise ValueError("CALLER_POLICIES_JSON contains an invalid caller policy")
            policies[appid] = CallerPolicy(
                appid=appid,
                display_name=str(entry.get("display_name", appid)),
                enabled=bool(entry.get("enabled", True)),
                maximum_severity=maximum_severity,
                maximum_concurrent_investigations=quota,
                allowed_resource_groups=frozenset(group.strip().lower() for group in resource_groups),
            )
        return cls(policies, default_quota, allow_unregistered)

    def get(self, appid: str) -> CallerPolicy:
        policy = self._policies.get(appid)
        if policy:
            return policy
        # Empty configuration preserves the existing local development behavior.
        if not self._policies and self._allow_unregistered:
            return CallerPolicy(
                appid=appid,
                display_name=appid,
                enabled=True,
                maximum_severity="critical",
                maximum_concurrent_investigations=self._default_quota,
                allowed_resource_groups=frozenset(),
            )
        raise ValueError("Caller is not registered for the escalation service")

    def authorize(self, appid: str, severity: str) -> CallerPolicy:
        policy = self.get(appid)
        if not policy.enabled:
            raise ValueError("Caller is disabled for the escalation service")
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[policy.maximum_severity]:
            raise ValueError(f"Requested severity exceeds caller policy limit ({policy.maximum_severity})")
        return policy

    def authorize_resource_group(self, appid: str, resource_group_id: str) -> CallerPolicy:
        policy = self.get(appid)
        normalized_resource_group_id = resource_group_id.strip().lower()
        if not policy.enabled:
            raise ValueError("Caller is disabled for the escalation service")
        if not RESOURCE_GROUP_ID_PATTERN.fullmatch(normalized_resource_group_id):
            raise ValueError("resource_group_id must be a valid Azure resource group ID")
        if normalized_resource_group_id not in policy.allowed_resource_groups:
            raise ValueError("Caller is not authorized for the requested resource group")
        return policy

    def health_check(self) -> None:
        return None


class RefreshingCallerPolicyStore:
    def __init__(
        self,
        endpoint: str,
        key: str,
        label: str,
        default_quota: int,
        refresh_interval_seconds: float,
        maximum_staleness_seconds: float,
        event_sink: Callable[..., None],
        client: AzureAppConfigurationClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._key = key
        self._label = label
        self._default_quota = default_quota
        self._refresh_interval_seconds = refresh_interval_seconds
        self._maximum_staleness_seconds = maximum_staleness_seconds
        self._event_sink = event_sink
        self._client = client or AzureAppConfigurationClient(endpoint, DefaultAzureCredential())
        self._clock = clock
        self._store: CallerPolicyStore | None = None
        self._etag: Any = None
        self._last_refresh_attempt = 0.0
        self._last_success = 0.0
        self._lock = Lock()
        try:
            self.refresh(force=True)
        except ValueError:
            pass

    def refresh(self, force: bool = False) -> float:
        with self._lock:
            now = self._clock()
            if not force and now - self._last_refresh_attempt < self._refresh_interval_seconds:
                return now
            self._last_refresh_attempt = now
            try:
                setting = self._client.get_configuration_setting(key=self._key, label=self._label or None)
                if setting is None:
                    raise ValueError("Caller policy setting was not found")
                if self._store is None or setting.etag != self._etag:
                    self._store = CallerPolicyStore.from_json(
                        setting.value or "",
                        self._default_quota,
                        allow_unregistered=False,
                    )
                    self._etag = setting.etag
                    self._event_sink("caller_policy_snapshot_updated", source="app_configuration")
                self._last_success = now
            except Exception as exc:
                cache_is_usable = (
                    self._store is not None and now - self._last_success <= self._maximum_staleness_seconds
                )
                self._event_sink(
                    "caller_policy_refresh_failed",
                    source="app_configuration",
                    using_last_known_good=cache_is_usable,
                    error_type=type(exc).__name__,
                )
                if not cache_is_usable:
                    raise ValueError("Caller policy is unavailable") from exc
            return now

    def _require_usable_snapshot(self, now: float) -> CallerPolicyStore:
        if self._store is None:
            raise ValueError("Caller policy is unavailable")
        if now - self._last_success > self._maximum_staleness_seconds:
            raise ValueError("Caller policy is unavailable")
        return self._store

    def get(self, appid: str) -> CallerPolicy:
        now = self.refresh()
        return self._require_usable_snapshot(now).get(appid)

    def authorize(self, appid: str, severity: str) -> CallerPolicy:
        now = self.refresh()
        return self._require_usable_snapshot(now).authorize(appid, severity)

    def authorize_resource_group(self, appid: str, resource_group_id: str) -> CallerPolicy:
        now = self.refresh()
        return self._require_usable_snapshot(now).authorize_resource_group(appid, resource_group_id)

    def health_check(self) -> None:
        now = self.refresh(force=True)
        self._require_usable_snapshot(now)
