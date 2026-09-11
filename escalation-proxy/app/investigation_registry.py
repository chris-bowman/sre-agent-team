import hashlib
import os
import random
import time
import uuid
from dataclasses import dataclass, field
from itertools import islice
from threading import Lock
from typing import Any

from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.data.tables import TableServiceClient, TableTransactionError, UpdateMode
from azure.identity import DefaultAzureCredential

import telemetry

REGISTRY_BACKEND = os.environ.get("REGISTRY_BACKEND", "memory").strip().lower()
REGISTRY_TABLE_ENDPOINT = os.environ.get("REGISTRY_TABLE_ENDPOINT", "").rstrip("/")
REGISTRY_TABLE_NAME = os.environ.get("REGISTRY_TABLE_NAME", "InvestigationRegistry")
MAX_EXPIRY_CLEANUP_BATCH_SIZE = int(os.environ.get("MAX_EXPIRY_CLEANUP_BATCH_SIZE", "100"))
ACTIVE_METADATA_RETENTION_SECONDS = max(int(os.environ.get("ACTIVE_METADATA_RETENTION_SECONDS", "86400")), 1)
FINAL_FINDINGS_METADATA_RETENTION_SECONDS = max(
    int(os.environ.get("FINAL_FINDINGS_METADATA_RETENTION_SECONDS", "604800")),
    1,
)
MAX_INVESTIGATIONS_PER_WORKLOAD = 100  # max concurrent
MIN_STATUS_POLL_INTERVAL_SECONDS = int(os.environ.get("MIN_STATUS_POLL_INTERVAL_SECONDS", "5"))
MAX_STATUS_POLLS_PER_INVESTIGATION = 288  # generous cap; long-polling means far fewer calls in practice


@dataclass
class InvestigationRecord:
    """Registry entry for an investigation."""

    investigation_id: str
    caller_oid: str  # Azure AD object ID of the creating caller
    caller_appid: str  # Application ID
    workload_name: str  # Sanitized workload name from request
    workload_identity_appid: str  # Legacy name for the caller service principal's app ID
    platform_thread_id: str  # Platform SRE Agent thread ID
    severity: str
    created_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp
    last_status_poll: float = 0.0  # Last time status was polled
    status_poll_count: int = 0  # Number of times status was polled
    request_correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    idempotency_key: str = ""
    request_fingerprint: str = ""
    reservation_state: str = "active"
    policy_display_name: str = ""
    policy_enabled: bool = True
    policy_maximum_severity: str = ""
    policy_maximum_concurrent_investigations: int = 0
    activated_at: float = 0.0
    completed_at: float = 0.0
    findings_finalized_at: float = 0.0
    findings_schema_version: str = ""
    findings_schema_valid: bool = False
    findings_selection_strategy: str = ""
    findings_redacted: bool = False


@dataclass(frozen=True)
class ReservationResult:
    investigation_id: str
    created: bool


class IdempotencyConflictError(ValueError):
    """A caller reused an idempotency key for a different request."""


class InvestigationRegistry:
    """Thread-safe registry of active investigations with ownership tracking."""

    def __init__(self):
        self._registry: dict[str, InvestigationRecord] = {}
        self._workload_investigations: dict[str, list[str]] = {}  # workload_name -> [investigation_ids]
        self._lock = Lock()

    def reserve_investigation(
        self,
        caller_oid: str,
        caller_appid: str,
        workload_name: str,
        workload_identity_appid: str,
        severity: str,
        maximum_investigations: int,
        idempotency_key: str = "",
        request_fingerprint: str = "",
        request_correlation_id: str = "",
        policy_display_name: str = "",
        policy_enabled: bool = True,
        policy_maximum_severity: str = "",
    ) -> ReservationResult:
        """Atomically reserve one caller quota slot before creating a platform thread."""
        with self._lock:
            self.cleanup_expired(MAX_EXPIRY_CLEANUP_BATCH_SIZE)
            now = time.time()
            if idempotency_key:
                existing = self.find_by_idempotency_key(caller_appid, idempotency_key)
                if existing:
                    if existing.request_fingerprint != request_fingerprint:
                        raise IdempotencyConflictError("Idempotency key was used with a different request")
                    return ReservationResult(existing.investigation_id, created=False)
            active_count = sum(
                1
                for record in self._registry.values()
                if record.workload_identity_appid == workload_identity_appid
                and now <= record.expires_at
                and record.reservation_state in {"reserved", "active"}
            )
            if active_count >= maximum_investigations:
                raise ValueError(f"Caller has reached maximum concurrent investigations ({maximum_investigations})")

            investigation_id = str(uuid.uuid4())
            record = InvestigationRecord(
                investigation_id=investigation_id,
                caller_oid=caller_oid,
                caller_appid=caller_appid,
                workload_name=workload_name,
                workload_identity_appid=workload_identity_appid,
                platform_thread_id="",
                severity=severity,
                created_at=now,
                expires_at=now + ACTIVE_METADATA_RETENTION_SECONDS,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                request_correlation_id=request_correlation_id or str(uuid.uuid4()),
                reservation_state="reserved",
                policy_display_name=policy_display_name,
                policy_enabled=policy_enabled,
                policy_maximum_severity=policy_maximum_severity,
                policy_maximum_concurrent_investigations=maximum_investigations,
            )
            self._registry[investigation_id] = record
            self._workload_investigations.setdefault(workload_name, []).append(investigation_id)
            return ReservationResult(investigation_id, created=True)

    def finalize_reservation(self, investigation_id: str, caller_appid: str, platform_thread_id: str) -> None:
        with self._lock:
            record = self._registry.get(investigation_id)
            if not record or record.caller_appid != caller_appid:
                raise ValueError("Investigation reservation was not found")
            record.platform_thread_id = platform_thread_id
            record.reservation_state = "active"
            record.activated_at = time.time()

    def release_reservation(self, investigation_id: str, caller_appid: str) -> None:
        with self._lock:
            record = self._registry.get(investigation_id)
            if record and record.caller_appid == caller_appid and record.reservation_state == "reserved":
                del self._registry[investigation_id]

    def complete_investigation(self, investigation_id: str, caller_appid: str, terminal_state: str) -> None:
        with self._lock:
            record = self._registry.get(investigation_id)
            if not record or record.caller_appid != caller_appid:
                raise ValueError("Investigation was not found")
            if record.reservation_state in {"reserved", "active"}:
                completed_at = time.time()
                record.reservation_state = terminal_state
                record.completed_at = completed_at
                record.expires_at = max(
                    record.expires_at,
                    completed_at + FINAL_FINDINGS_METADATA_RETENTION_SECONDS,
                )

    def record_findings_metadata(
        self,
        investigation_id: str,
        caller_appid: str,
        schema_valid: bool,
        selection_strategy: str,
        redaction_applied: bool,
    ) -> None:
        with self._lock:
            record = self._registry.get(investigation_id)
            if not record or record.caller_appid != caller_appid:
                raise ValueError("Investigation was not found")
            if record.findings_finalized_at == 0.0:
                record.findings_finalized_at = time.time()
                record.expires_at = max(
                    record.expires_at,
                    record.findings_finalized_at + FINAL_FINDINGS_METADATA_RETENTION_SECONDS,
                )
            record.findings_schema_version = "1.0" if schema_valid else ""
            record.findings_schema_valid = schema_valid
            record.findings_selection_strategy = selection_strategy
            record.findings_redacted = redaction_applied

    def create_investigation(
        self,
        caller_oid: str,
        caller_appid: str,
        workload_name: str,
        workload_identity_appid: str,
        platform_thread_id: str,
        severity: str,
        idempotency_key: str = "",
        request_fingerprint: str = "",
        request_correlation_id: str = "",
    ) -> str:
        """Register a new investigation. Returns the investigation_id."""
        reservation = self.reserve_investigation(
            caller_oid,
            caller_appid,
            workload_name,
            workload_identity_appid,
            severity,
            MAX_INVESTIGATIONS_PER_WORKLOAD,
            idempotency_key,
            request_fingerprint,
            request_correlation_id,
        )
        self.finalize_reservation(reservation.investigation_id, caller_appid, platform_thread_id)
        return reservation.investigation_id

    def get_investigation(
        self, investigation_id: str, caller_oid: str, workload_identity_appid: str
    ) -> InvestigationRecord:
        """Retrieve an investigation, verifying ownership. Raises ValueError if not found or unauthorized."""
        record = self._registry.get(investigation_id)
        if not record:
            raise ValueError(f"Investigation {investigation_id} not found")

        # Verify ownership against the caller that created the investigation.
        if record.workload_identity_appid != workload_identity_appid:
            telemetry.log_event(
                "investigation_access_denied",
                investigation_id=investigation_id,
                reason="caller_workload_identity_mismatch",
                expected_appid=record.workload_identity_appid,
                provided_appid=workload_identity_appid,
            )
            raise ValueError("Unauthorized: investigation belongs to a different caller")

        # Check expiry.
        if time.time() > record.expires_at:
            telemetry.log_event(
                "investigation_expired",
                investigation_id=investigation_id,
                created_at=record.created_at,
                expired_at=record.expires_at,
            )
            del self._registry[investigation_id]
            raise ValueError(f"Investigation {investigation_id} has expired")

        return record

    def find_by_idempotency_key(self, caller_appid: str, idempotency_key: str) -> InvestigationRecord | None:
        for record in self._registry.values():
            if (
                record.caller_appid == caller_appid
                and record.idempotency_key == idempotency_key
                and time.time() <= record.expires_at
                and record.reservation_state in {"reserved", "active"}
            ):
                return record
        return None

    def record_status_poll(self, investigation_id: str, caller_oid: str, workload_identity_appid: str) -> None:
        """Record a status poll and enforce rate limits. Raises ValueError on limit violations."""
        record = self.get_investigation(investigation_id, caller_oid, workload_identity_appid)
        now = time.time()

        # Enforce minimum poll interval.
        if record.last_status_poll > 0 and (now - record.last_status_poll) < MIN_STATUS_POLL_INTERVAL_SECONDS:
            raise ValueError(f"Status poll rate limit: minimum {MIN_STATUS_POLL_INTERVAL_SECONDS}s between polls")

        # Enforce maximum poll count.
        if record.status_poll_count >= MAX_STATUS_POLLS_PER_INVESTIGATION:
            raise ValueError(
                f"Investigation {investigation_id} has reached maximum status polls ({MAX_STATUS_POLLS_PER_INVESTIGATION})"
            )

        record.last_status_poll = now
        record.status_poll_count += 1

    def check_workload_quota(self, workload_identity_appid: str, maximum_investigations: int | None = None) -> None:
        """Check if a caller has reached its investigation quota. Raises ValueError if exceeded."""
        quota = maximum_investigations or MAX_INVESTIGATIONS_PER_WORKLOAD
        active_count = sum(
            1
            for rec in self._registry.values()
            if rec.workload_identity_appid == workload_identity_appid
            and time.time() <= rec.expires_at
            and rec.reservation_state in {"reserved", "active"}
        )
        if active_count >= quota:
            raise ValueError(f"Caller has reached maximum concurrent investigations ({quota})")

    def cleanup_expired(self, limit: int = MAX_EXPIRY_CLEANUP_BATCH_SIZE) -> int:
        """Remove up to limit expired investigations. Returns the count removed."""
        now = time.time()
        expired = [investigation_id for investigation_id, record in self._registry.items() if now > record.expires_at][
            :limit
        ]
        for id in expired:
            del self._registry[id]
        return len(expired)

    def health_check(self) -> None:
        """Memory backend is ready when the process is serving."""


class TableStorageInvestigationRegistry:
    """Azure Table-backed registry with the same contract as the memory backend."""

    def __init__(self, endpoint: str, table_name: str):
        if not endpoint:
            raise ValueError("REGISTRY_TABLE_ENDPOINT is required for table backend")
        service = TableServiceClient(endpoint=endpoint, credential=DefaultAzureCredential())
        self._table = service.get_table_client(table_name)

    @staticmethod
    def _partition_key(workload_identity_appid: str) -> str:
        return workload_identity_appid

    @staticmethod
    def _quota_counter_key() -> str:
        return "__quota_counter__"

    @staticmethod
    def _idempotency_index_key(idempotency_key: str) -> str:
        return f"__idempotency__{hashlib.sha256(idempotency_key.encode('utf-8')).hexdigest()}"

    @staticmethod
    def _entity_etag(entity: dict[str, Any]) -> str:
        """Read the SDK concurrency tag across TableEntity representations."""
        metadata = getattr(entity, "metadata", None) or getattr(entity, "_metadata", None) or {}
        etag = metadata.get("etag") or entity.get("etag") or entity.get("_etag")
        if not etag:
            raise ValueError("Table entity is missing an ETag for a conditional mutation")
        return str(etag)

    @staticmethod
    def _escape_odata_string(value: str) -> str:
        return value.replace("'", "''")

    @staticmethod
    def _is_concurrency_conflict(error: Exception) -> bool:
        return isinstance(error, ResourceModifiedError) or (
            isinstance(error, TableTransactionError) and getattr(error, "status_code", None) == 412
        )

    def _get_or_create_quota_counter(self, caller_appid: str) -> dict[str, Any]:
        try:
            return self._table.get_entity(self._partition_key(caller_appid), self._quota_counter_key())
        except ResourceNotFoundError:
            counter = {
                "PartitionKey": self._partition_key(caller_appid),
                "RowKey": self._quota_counter_key(),
                "active_count": 0,
            }
            try:
                self._table.create_entity(counter)
            except ResourceExistsError:
                pass
            return self._table.get_entity(self._partition_key(caller_appid), self._quota_counter_key())

    def _decrement_quota_counter(self, caller_appid: str) -> None:
        for _attempt in range(3):
            counter = self._get_or_create_quota_counter(caller_appid)
            updated = dict(counter)
            updated["active_count"] = max(0, int(counter.get("active_count", 0)) - 1)
            try:
                self._table.update_entity(
                    updated,
                    mode=UpdateMode.REPLACE,
                    etag=self._entity_etag(counter),
                    match_condition=MatchConditions.IfNotModified,
                )
                return
            except ResourceModifiedError:
                telemetry.log_event("table_quota_counter_conflict", operation="decrement", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Quota counter update conflicted; please retry")

    def _reconcile_quota_counter(self, caller_appid: str, counter: dict[str, Any]) -> bool:
        now = time.time()
        active_count = sum(
            1
            for entity in self._table.query_entities(
                query_filter=f"PartitionKey eq '{self._partition_key(caller_appid)}'"
            )
            if entity.get("RowKey") != self._quota_counter_key()
            and float(entity.get("expires_at", 0)) >= now
            and entity.get("reservation_state", "active") in {"reserved", "active"}
        )
        if active_count == int(counter.get("active_count", 0)):
            return False

        updated = dict(counter)
        updated["active_count"] = active_count
        self._table.update_entity(
            updated,
            mode=UpdateMode.REPLACE,
            etag=self._entity_etag(counter),
            match_condition=MatchConditions.IfNotModified,
        )
        telemetry.log_event(
            "table_quota_counter_reconciled",
            previous_count=int(counter.get("active_count", 0)),
            active_count=active_count,
        )
        return True

    @staticmethod
    def _to_entity(record: InvestigationRecord) -> dict[str, Any]:
        return {
            "PartitionKey": record.workload_identity_appid,
            "RowKey": record.investigation_id,
            "caller_oid": record.caller_oid,
            "caller_appid": record.caller_appid,
            "workload_name": record.workload_name,
            "workload_identity_appid": record.workload_identity_appid,
            "platform_thread_id": record.platform_thread_id,
            "severity": record.severity,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "last_status_poll": record.last_status_poll,
            "status_poll_count": record.status_poll_count,
            "request_correlation_id": record.request_correlation_id,
            "idempotency_key": record.idempotency_key,
            "request_fingerprint": record.request_fingerprint,
            "reservation_state": record.reservation_state,
            "policy_display_name": record.policy_display_name,
            "policy_enabled": record.policy_enabled,
            "policy_maximum_severity": record.policy_maximum_severity,
            "policy_maximum_concurrent_investigations": record.policy_maximum_concurrent_investigations,
            "activated_at": record.activated_at,
            "completed_at": record.completed_at,
            "findings_finalized_at": record.findings_finalized_at,
            "findings_schema_version": record.findings_schema_version,
            "findings_schema_valid": record.findings_schema_valid,
            "findings_selection_strategy": record.findings_selection_strategy,
            "findings_redacted": record.findings_redacted,
        }

    @staticmethod
    def _from_entity(entity: dict[str, Any]) -> InvestigationRecord:
        return InvestigationRecord(
            investigation_id=entity["RowKey"],
            caller_oid=entity["caller_oid"],
            caller_appid=entity["caller_appid"],
            workload_name=entity["workload_name"],
            workload_identity_appid=entity["workload_identity_appid"],
            platform_thread_id=entity["platform_thread_id"],
            severity=entity["severity"],
            created_at=float(entity["created_at"]),
            expires_at=float(entity["expires_at"]),
            last_status_poll=float(entity.get("last_status_poll", 0.0)),
            status_poll_count=int(entity.get("status_poll_count", 0)),
            request_correlation_id=entity.get("request_correlation_id", str(uuid.uuid4())),
            idempotency_key=entity.get("idempotency_key", ""),
            request_fingerprint=entity.get("request_fingerprint", ""),
            reservation_state=entity.get("reservation_state", "active"),
            policy_display_name=entity.get("policy_display_name", ""),
            policy_enabled=bool(entity.get("policy_enabled", True)),
            policy_maximum_severity=entity.get("policy_maximum_severity", ""),
            policy_maximum_concurrent_investigations=int(entity.get("policy_maximum_concurrent_investigations", 0)),
            activated_at=float(entity.get("activated_at", 0.0)),
            completed_at=float(entity.get("completed_at", 0.0)),
            findings_finalized_at=float(entity.get("findings_finalized_at", 0.0)),
            findings_schema_version=entity.get("findings_schema_version", ""),
            findings_schema_valid=bool(entity.get("findings_schema_valid", False)),
            findings_selection_strategy=entity.get("findings_selection_strategy", ""),
            findings_redacted=bool(entity.get("findings_redacted", False)),
        )

    def reserve_investigation(
        self,
        caller_oid: str,
        caller_appid: str,
        workload_name: str,
        workload_identity_appid: str,
        severity: str,
        maximum_investigations: int,
        idempotency_key: str = "",
        request_fingerprint: str = "",
        request_correlation_id: str = "",
        policy_display_name: str = "",
        policy_enabled: bool = True,
        policy_maximum_severity: str = "",
    ) -> ReservationResult:
        """Atomically reserve a Table slot and increment its per-caller quota counter."""
        self.cleanup_expired(MAX_EXPIRY_CLEANUP_BATCH_SIZE)
        now = time.time()
        record = InvestigationRecord(
            investigation_id=str(uuid.uuid4()),
            caller_oid=caller_oid,
            caller_appid=caller_appid,
            workload_name=workload_name,
            workload_identity_appid=workload_identity_appid,
            platform_thread_id="",
            severity=severity,
            created_at=now,
            expires_at=now + ACTIVE_METADATA_RETENTION_SECONDS,
            idempotency_key=idempotency_key,
            request_correlation_id=request_correlation_id or str(uuid.uuid4()),
            request_fingerprint=request_fingerprint,
            reservation_state="reserved",
            policy_display_name=policy_display_name,
            policy_enabled=policy_enabled,
            policy_maximum_severity=policy_maximum_severity,
            policy_maximum_concurrent_investigations=maximum_investigations,
        )
        for _attempt in range(3):
            counter = self._get_or_create_quota_counter(workload_identity_appid)
            active_count = int(counter.get("active_count", 0))
            if active_count >= maximum_investigations:
                try:
                    if self._reconcile_quota_counter(workload_identity_appid, counter):
                        continue
                except ResourceModifiedError:
                    telemetry.log_event(
                        "table_quota_counter_conflict",
                        operation="reconcile",
                        attempt=_attempt + 1,
                    )
                    time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                    continue
                raise ValueError(f"Caller has reached maximum concurrent investigations ({maximum_investigations})")
            updated_counter = dict(counter)
            updated_counter["active_count"] = active_count + 1
            try:
                operations = [
                    (
                        "update",
                        updated_counter,
                        {
                            "mode": UpdateMode.REPLACE,
                            "etag": self._entity_etag(counter),
                            "match_condition": MatchConditions.IfNotModified,
                        },
                    ),
                    ("create", self._to_entity(record)),
                ]
                if idempotency_key:
                    operations.append(
                        (
                            "create",
                            {
                                "PartitionKey": self._partition_key(caller_appid),
                                "RowKey": self._idempotency_index_key(idempotency_key),
                                "investigation_id": record.investigation_id,
                                "request_fingerprint": request_fingerprint,
                                "expires_at": record.expires_at,
                            },
                        )
                    )
                self._table.submit_transaction(operations)
                return ReservationResult(record.investigation_id, created=True)
            except (ResourceModifiedError, TableTransactionError) as exc:
                if (
                    idempotency_key
                    and isinstance(exc, TableTransactionError)
                    and getattr(exc, "status_code", None) == 409
                ):
                    existing = self._get_idempotency_record(caller_appid, idempotency_key)
                    if existing is None:
                        raise ValueError("Idempotency reservation could not be recovered") from exc
                    if existing.request_fingerprint != request_fingerprint:
                        raise IdempotencyConflictError("Idempotency key was used with a different request") from exc
                    return ReservationResult(existing.investigation_id, created=False)
                if not self._is_concurrency_conflict(exc):
                    raise
                telemetry.log_event("table_quota_counter_conflict", operation="reserve", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Quota reservation conflicted; please retry")

    def finalize_reservation(self, investigation_id: str, caller_appid: str, platform_thread_id: str) -> None:
        for _attempt in range(3):
            entity = self._table.get_entity(self._partition_key(caller_appid), investigation_id)
            record = self._from_entity(entity)
            if record.caller_appid != caller_appid:
                raise ValueError("Investigation reservation was not found")
            record.platform_thread_id = platform_thread_id
            record.reservation_state = "active"
            record.activated_at = time.time()
            try:
                self._table.update_entity(
                    self._to_entity(record),
                    mode=UpdateMode.REPLACE,
                    etag=self._entity_etag(entity),
                    match_condition=MatchConditions.IfNotModified,
                )
                return
            except ResourceModifiedError:
                telemetry.log_event("table_investigation_conflict", operation="finalize", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Investigation reservation update conflicted; please retry")

    def release_reservation(self, investigation_id: str, caller_appid: str) -> None:
        for _attempt in range(3):
            try:
                entity = self._table.get_entity(self._partition_key(caller_appid), investigation_id)
            except ResourceNotFoundError:
                return
            if entity.get("caller_appid") != caller_appid or entity.get("reservation_state") != "reserved":
                return
            try:
                self._table.delete_entity(
                    entity["PartitionKey"],
                    entity["RowKey"],
                    etag=self._entity_etag(entity),
                    match_condition=MatchConditions.IfNotModified,
                )
                self._decrement_quota_counter(caller_appid)
                return
            except ResourceModifiedError:
                telemetry.log_event("table_investigation_conflict", operation="release", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Investigation reservation cleanup conflicted; please retry")

    def complete_investigation(self, investigation_id: str, caller_appid: str, terminal_state: str) -> None:
        for _attempt in range(3):
            entity = self._table.get_entity(self._partition_key(caller_appid), investigation_id)
            if entity.get("caller_appid") != caller_appid:
                raise ValueError("Investigation was not found")
            if entity.get("reservation_state") not in {"reserved", "active"}:
                return

            counter = self._get_or_create_quota_counter(caller_appid)
            updated_entity = dict(entity)
            completed_at = time.time()
            updated_entity["reservation_state"] = terminal_state
            updated_entity["completed_at"] = completed_at
            updated_entity["expires_at"] = max(
                float(entity.get("expires_at", 0.0)),
                completed_at + FINAL_FINDINGS_METADATA_RETENTION_SECONDS,
            )
            updated_counter = dict(counter)
            updated_counter["active_count"] = max(0, int(counter.get("active_count", 0)) - 1)
            try:
                self._table.submit_transaction(
                    [
                        (
                            "update",
                            updated_counter,
                            {
                                "mode": UpdateMode.REPLACE,
                                "etag": self._entity_etag(counter),
                                "match_condition": MatchConditions.IfNotModified,
                            },
                        ),
                        (
                            "update",
                            updated_entity,
                            {
                                "mode": UpdateMode.REPLACE,
                                "etag": self._entity_etag(entity),
                                "match_condition": MatchConditions.IfNotModified,
                            },
                        ),
                    ]
                )
                return
            except (ResourceModifiedError, TableTransactionError) as exc:
                if not self._is_concurrency_conflict(exc):
                    raise
                telemetry.log_event("table_investigation_conflict", operation="complete", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Investigation completion update conflicted; please retry")

    def record_findings_metadata(
        self,
        investigation_id: str,
        caller_appid: str,
        schema_valid: bool,
        selection_strategy: str,
        redaction_applied: bool,
    ) -> None:
        for _attempt in range(3):
            entity = self._table.get_entity(self._partition_key(caller_appid), investigation_id)
            if entity.get("caller_appid") != caller_appid:
                raise ValueError("Investigation was not found")
            updated_entity = dict(entity)
            if float(entity.get("findings_finalized_at", 0.0)) == 0.0:
                updated_entity["findings_finalized_at"] = time.time()
                updated_entity["expires_at"] = max(
                    float(entity.get("expires_at", 0.0)),
                    updated_entity["findings_finalized_at"] + FINAL_FINDINGS_METADATA_RETENTION_SECONDS,
                )
            updated_entity["findings_schema_version"] = "1.0" if schema_valid else ""
            updated_entity["findings_schema_valid"] = schema_valid
            updated_entity["findings_selection_strategy"] = selection_strategy
            updated_entity["findings_redacted"] = redaction_applied
            try:
                self._table.update_entity(
                    updated_entity,
                    mode=UpdateMode.REPLACE,
                    etag=self._entity_etag(entity),
                    match_condition=MatchConditions.IfNotModified,
                )
                return
            except ResourceModifiedError:
                telemetry.log_event("table_investigation_conflict", operation="findings_metadata", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Investigation findings update conflicted; please retry")

    def create_investigation(
        self,
        caller_oid: str,
        caller_appid: str,
        workload_name: str,
        workload_identity_appid: str,
        platform_thread_id: str,
        severity: str,
        idempotency_key: str = "",
        request_fingerprint: str = "",
        request_correlation_id: str = "",
    ) -> str:
        reservation = self.reserve_investigation(
            caller_oid,
            caller_appid,
            workload_name,
            workload_identity_appid,
            severity,
            MAX_INVESTIGATIONS_PER_WORKLOAD,
            idempotency_key,
            request_fingerprint,
            request_correlation_id,
        )
        self.finalize_reservation(reservation.investigation_id, caller_appid, platform_thread_id)
        return reservation.investigation_id

    def _get_idempotency_record(self, caller_appid: str, idempotency_key: str) -> InvestigationRecord | None:
        try:
            index = self._table.get_entity(
                self._partition_key(caller_appid), self._idempotency_index_key(idempotency_key)
            )
            return self.get_investigation(index["investigation_id"], "", caller_appid)
        except ResourceNotFoundError:
            return None

    def find_by_idempotency_key(self, caller_appid: str, idempotency_key: str) -> InvestigationRecord | None:
        indexed_record = self._get_idempotency_record(caller_appid, idempotency_key)
        if indexed_record is not None:
            return indexed_record
        partition_key = self._escape_odata_string(self._partition_key(caller_appid))
        escaped_key = self._escape_odata_string(idempotency_key)
        entities = self._table.query_entities(
            query_filter=(f"PartitionKey eq '{partition_key}' and idempotency_key eq '{escaped_key}'")
        )
        for entity in entities:
            record = self._from_entity(entity)
            if (
                record.caller_appid == caller_appid
                and record.workload_identity_appid == caller_appid
                and time.time() <= record.expires_at
            ):
                return record
        return None

    def get_investigation(
        self, investigation_id: str, caller_oid: str, workload_identity_appid: str
    ) -> InvestigationRecord:
        try:
            entity = self._table.get_entity(self._partition_key(workload_identity_appid), investigation_id)
        except ResourceNotFoundError:
            raise ValueError(f"Investigation {investigation_id} not found")
        record = self._from_entity(entity)
        if record.workload_identity_appid != workload_identity_appid:
            telemetry.log_event(
                "investigation_access_denied",
                investigation_id=investigation_id,
                reason="caller_workload_identity_mismatch",
                provided_appid=workload_identity_appid,
            )
            raise ValueError("Unauthorized: investigation belongs to a different caller")
        if time.time() > record.expires_at:
            self._table.delete_entity(entity["PartitionKey"], entity["RowKey"])
            raise ValueError(f"Investigation {investigation_id} has expired")
        return record

    def record_status_poll(self, investigation_id: str, caller_oid: str, workload_identity_appid: str) -> None:
        for _attempt in range(3):
            try:
                entity = self._table.get_entity(self._partition_key(workload_identity_appid), investigation_id)
                record = self._from_entity(entity)
                if record.workload_identity_appid != workload_identity_appid:
                    telemetry.log_event(
                        "investigation_access_denied",
                        investigation_id=investigation_id,
                        reason="caller_workload_identity_mismatch",
                        provided_appid=workload_identity_appid,
                    )
                    raise ValueError("Unauthorized: investigation belongs to a different caller")
                if time.time() > record.expires_at:
                    self._table.delete_entity(entity["PartitionKey"], entity["RowKey"])
                    raise ValueError(f"Investigation {investigation_id} has expired")
                now = time.time()
                if record.last_status_poll > 0 and now - record.last_status_poll < MIN_STATUS_POLL_INTERVAL_SECONDS:
                    raise ValueError(
                        f"Status poll rate limit: minimum {MIN_STATUS_POLL_INTERVAL_SECONDS}s between polls"
                    )
                if record.status_poll_count >= MAX_STATUS_POLLS_PER_INVESTIGATION:
                    raise ValueError(
                        f"Investigation {investigation_id} has reached maximum status polls ({MAX_STATUS_POLLS_PER_INVESTIGATION})"
                    )
                record.last_status_poll = now
                record.status_poll_count += 1
                self._table.update_entity(
                    self._to_entity(record),
                    mode=UpdateMode.REPLACE,
                    etag=self._entity_etag(entity),
                    match_condition=MatchConditions.IfNotModified,
                )
                return
            except ResourceModifiedError:
                telemetry.log_event("table_investigation_conflict", operation="status_poll", attempt=_attempt + 1)
                time.sleep((0.05 * (2**_attempt)) + random.uniform(0, 0.05))
                continue
        raise ValueError("Status poll update conflicted; please retry")

    def check_workload_quota(self, workload_identity_appid: str, maximum_investigations: int | None = None) -> None:
        quota = maximum_investigations or MAX_INVESTIGATIONS_PER_WORKLOAD
        now = time.time()
        active_count = sum(
            1
            for entity in self._table.query_entities(query_filter=f"PartitionKey eq '{workload_identity_appid}'")
            if entity.get("RowKey") != self._quota_counter_key()
            and float(entity.get("expires_at", 0)) >= now
            and entity.get("reservation_state", "active") in {"reserved", "active"}
        )
        if active_count >= quota:
            raise ValueError(f"Caller has reached maximum concurrent investigations ({quota})")

    def cleanup_expired(self, limit: int = MAX_EXPIRY_CLEANUP_BATCH_SIZE) -> int:
        now = time.time()
        expired = [
            entity
            for entity in islice(
                self._table.query_entities(query_filter=f"expires_at lt {now}"),
                limit,
            )
            if entity.get("RowKey") != self._quota_counter_key() and float(entity.get("expires_at", 0)) < now
        ]
        deleted_count = 0
        for entity in expired:
            try:
                self._table.delete_entity(entity["PartitionKey"], entity["RowKey"])
            except ResourceNotFoundError:
                continue
            deleted_count += 1
            if entity.get("reservation_state", "active") in {"reserved", "active"} and entity.get("caller_appid"):
                self._decrement_quota_counter(entity["caller_appid"])
        return deleted_count

    def health_check(self) -> None:
        """Perform a bounded data-plane query to verify table access."""
        next(iter(self._table.list_entities(results_per_page=1)), None)


def build_investigation_registry() -> InvestigationRegistry | TableStorageInvestigationRegistry:
    if REGISTRY_BACKEND == "table":
        return TableStorageInvestigationRegistry(REGISTRY_TABLE_ENDPOINT, REGISTRY_TABLE_NAME)
    if REGISTRY_BACKEND != "memory":
        raise ValueError("REGISTRY_BACKEND must be 'memory' or 'table'")
    return InvestigationRegistry()
