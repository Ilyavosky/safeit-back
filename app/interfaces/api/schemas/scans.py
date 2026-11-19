from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.domain.entities.finding import Finding
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.severity import Severity


class ScanResponse(BaseModel):
    id: UUID
    domain_id: UUID
    type: ScanType
    status: JobStatus
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanResponse":
        return cls(
            id=scan.id,
            domain_id=scan.domain_id,
            type=scan.type,
            status=scan.status,
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
        )


class TestRunResponse(BaseModel):
    __test__ = False

    id: UUID
    endpoint_id: UUID
    tool: str
    params: dict[str, Any]
    status: JobStatus
    started_at: datetime | None
    finished_at: datetime | None

    @classmethod
    def from_run(cls, run: TestRun) -> "TestRunResponse":
        return cls(
            id=run.id,
            endpoint_id=run.endpoint_id,
            tool=run.tool_name,
            params=run.params,
            status=run.status,
            started_at=run.started_at,
            finished_at=run.finished_at,
        )


class FindingResponse(BaseModel):
    id: UUID
    test_run_id: UUID
    endpoint_id: UUID
    title: str
    severity: Severity
    priority_score: float | None
    remediation_status: RemediationStatus
    is_false_positive: bool
    cve_ids: list[str]
    detected_at: datetime

    @classmethod
    def from_finding(cls, finding: Finding) -> "FindingResponse":
        return cls(
            id=finding.id,
            test_run_id=finding.test_run_id,
            endpoint_id=finding.endpoint_id,
            title=finding.title,
            severity=finding.severity,
            priority_score=finding.priority_score,
            remediation_status=finding.remediation_status,
            is_false_positive=finding.is_false_positive,
            cve_ids=list(finding.cve_ids),
            detected_at=finding.detected_at,
        )
