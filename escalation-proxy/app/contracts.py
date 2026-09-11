"""Shared domain contracts for HTTP and MCP transports."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_SCHEMA_VERSION: Literal["1.0"] = "1.0"
InvestigationStatus = Literal["pending", "running", "completed", "failed", "expired"]
Severity = Literal["low", "medium", "high", "critical"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateInvestigationV1Request(ContractModel):
    description: str = Field(min_length=1, max_length=5000)
    caller_label: str = Field(min_length=1, max_length=256)
    severity: Severity = "medium"
    context: str = Field(default="", max_length=10000)


class V1StatusRequest(ContractModel):
    wait_seconds: int = Field(default=0, ge=0)


class ProblemDetails(ContractModel):
    type: str
    title: str
    status: int = Field(ge=400, le=599)
    code: str
    detail: str
    correlation_id: UUID
    retryable: bool
    retry_after_seconds: int | None = Field(default=None, ge=0)


class InvestigationLifecycleResponse(ContractModel):
    schema_version: Literal["1.0"] = CONTRACT_SCHEMA_VERSION
    investigation_id: UUID
    status: InvestigationStatus
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    correlation_id: UUID
    poll_after_seconds: int = Field(ge=0)
    failure: ProblemDetails | None = None


class InvestigationFindings(ContractModel):
    summary: str
    impact: str
    evidence: list[str]
    likely_causes: list[str]
    recommended_actions: list[str]
    limitations: list[str]


class InvestigationFindingsResponse(ContractModel):
    schema_version: Literal["1.0"] = CONTRACT_SCHEMA_VERSION
    investigation_id: UUID
    status: Literal["completed"]
    created_at: datetime
    completed_at: datetime
    expires_at: datetime
    correlation_id: UUID
    findings: InvestigationFindings


class CallerRegistration(ContractModel):
    schema_version: Literal["1.0"] = CONTRACT_SCHEMA_VERSION
    caller_appid: UUID
    display_name: str = Field(min_length=1)
    enabled: bool
    maximum_severity: Severity
    maximum_concurrent_investigations: int = Field(ge=1)
    created_at: datetime
    created_by: str = Field(min_length=1)
    updated_at: datetime
    updated_by: str = Field(min_length=1)


class CreateInvestigationRequest(BaseModel):
    """Legacy request accepted by compatibility transports."""

    description: str
    workload_name: str
    severity: str = "medium"
    context: str = ""


class GetInvestigationRequest(BaseModel):
    investigation_id: str
    wait_seconds: int = 0


class RedactedSummaryResponse(BaseModel):
    """Stable public contract for findings returned to callers."""

    schema_version: str = "1.0"
    investigation_id: str
    status: str
    summary: str
