"""Contract tests for the versioned public domain models."""

import pytest
from pydantic import ValidationError

from contracts import (
    CallerRegistration,
    CreateInvestigationV1Request,
    InvestigationFindingsResponse,
    InvestigationLifecycleResponse,
    ProblemDetails,
)

LIFECYCLE = {
    "investigation_id": "f57afdb4-348f-40aa-b29d-886f4bce5332",
    "status": "running",
    "created_at": "2026-08-26T18:42:00Z",
    "updated_at": "2026-08-26T18:43:12Z",
    "expires_at": "2026-08-27T18:42:00Z",
    "correlation_id": "4db79a5a-6ba6-4c11-9090-5d62286e7cb3",
    "poll_after_seconds": 30,
}


def test_lifecycle_contract_serializes_canonical_shape():
    response = InvestigationLifecycleResponse.model_validate(LIFECYCLE)

    assert response.model_dump(mode="json") == {
        "schema_version": "1.0",
        **LIFECYCLE,
        "failure": None,
    }


def test_lifecycle_contract_rejects_unknown_status_and_fields():
    with pytest.raises(ValidationError):
        InvestigationLifecycleResponse.model_validate(
            {**LIFECYCLE, "status": "succeeded", "platform_thread_id": "private-thread"}
        )


def test_findings_contract_allows_only_public_findings_fields():
    payload = {
        **{key: value for key, value in LIFECYCLE.items() if key not in {"status", "updated_at", "poll_after_seconds"}},
        "status": "completed",
        "completed_at": "2026-08-26T18:47:31Z",
        "findings": {
            "summary": "Private DNS resolution failed.",
            "impact": "Connections to the shared API failed.",
            "evidence": ["The virtual network link was absent."],
            "likely_causes": ["A network deployment removed the link."],
            "recommended_actions": ["Restore and validate the link."],
            "limitations": ["No configuration was changed."],
        },
    }

    response = InvestigationFindingsResponse.model_validate(payload)
    assert response.status == "completed"

    payload["findings"]["platform_thread_id"] = "private-thread"
    with pytest.raises(ValidationError):
        InvestigationFindingsResponse.model_validate(payload)


def test_request_problem_and_registration_constraints_are_enforced():
    request = CreateInvestigationV1Request(
        description="Investigate failed private endpoint resolution.",
        caller_label="payments-prod",
        resource_group_id="/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/payments-prod",
    )
    assert request.severity == "medium"

    with pytest.raises(ValidationError):
        CreateInvestigationV1Request(description="x" * 5001, caller_label="payments-prod", resource_group_id="rg")

    with pytest.raises(ValidationError):
        CreateInvestigationV1Request(description="valid", caller_label="x" * 257, resource_group_id="rg")

    with pytest.raises(ValidationError):
        ProblemDetails(
            type="urn:problem:quota",
            title="Quota exceeded",
            status=429,
            code="quota_exceeded",
            detail="Concurrent quota exhausted.",
            correlation_id=LIFECYCLE["correlation_id"],
            retryable=True,
            retry_after_seconds=-1,
        )

    registration = CallerRegistration(
        caller_appid="00000000-0000-0000-0000-000000000001",
        display_name="Payments production SRE",
        enabled=True,
        maximum_severity="high",
        maximum_concurrent_investigations=3,
        allowed_resource_groups=["/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/payments-prod"],
        created_at=LIFECYCLE["created_at"],
        created_by="platform-operator@example.com",
        updated_at=LIFECYCLE["updated_at"],
        updated_by="platform-operator@example.com",
    )
    assert registration.maximum_concurrent_investigations == 3
