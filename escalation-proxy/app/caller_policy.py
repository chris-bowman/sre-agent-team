"""Operator-owned authorization policy for same-tenant escalation callers."""

import json
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class CallerPolicy:
    appid: str
    display_name: str
    enabled: bool
    maximum_severity: str
    maximum_concurrent_investigations: int


class CallerPolicyStore:
    def __init__(self, policies: dict[str, CallerPolicy], default_quota: int):
        self._policies = policies
        self._default_quota = default_quota

    @classmethod
    def from_json(cls, raw: str, default_quota: int) -> "CallerPolicyStore":
        if not raw.strip():
            return cls({}, default_quota)

        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            raise ValueError("CALLER_POLICIES_JSON must be a JSON array")

        policies = {}
        for entry in parsed:
            appid = str(entry["appid"]).strip()
            maximum_severity = str(entry.get("maximum_severity", "critical")).strip().lower()
            quota = int(entry.get("maximum_concurrent_investigations", default_quota))
            if not appid or maximum_severity not in SEVERITY_ORDER or quota < 1:
                raise ValueError("CALLER_POLICIES_JSON contains an invalid caller policy")
            policies[appid] = CallerPolicy(
                appid=appid,
                display_name=str(entry.get("display_name", appid)),
                enabled=bool(entry.get("enabled", True)),
                maximum_severity=maximum_severity,
                maximum_concurrent_investigations=quota,
            )
        return cls(policies, default_quota)

    def get(self, appid: str) -> CallerPolicy:
        policy = self._policies.get(appid)
        if policy:
            return policy
        # Empty configuration preserves the existing local development behavior.
        if not self._policies:
            return CallerPolicy(
                appid=appid,
                display_name=appid,
                enabled=True,
                maximum_severity="critical",
                maximum_concurrent_investigations=self._default_quota,
            )
        raise ValueError("Caller is not registered for the escalation service")

    def authorize(self, appid: str, severity: str) -> CallerPolicy:
        policy = self.get(appid)
        if not policy.enabled:
            raise ValueError("Caller is disabled for the escalation service")
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[policy.maximum_severity]:
            raise ValueError(f"Requested severity exceeds caller policy limit ({policy.maximum_severity})")
        return policy
