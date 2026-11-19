from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class Finding:
    id: UUID
    test_run_id: UUID
    endpoint_id: UUID
    title: str
    severity: Severity
    priority_score: float | None
    remediation_status: RemediationStatus
    detected_at: datetime
    cve_ids: tuple[str, ...] = ()
    is_false_positive: bool = False
