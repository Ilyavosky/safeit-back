from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.application.ports.findings_query import FindingPage, FindingView
from app.domain.value_objects.finding_lifecycle import FindingLifecycle
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity


class FindingDetailResponse(BaseModel):
    id: UUID
    title: str
    severity: Severity
    priority_score: float | None
    remediation_status: RemediationStatus
    status: FindingLifecycle
    is_false_positive: bool
    cve_ids: list[str]
    detected_at: datetime
    domain_id: UUID
    domain: str
    asset_id: UUID
    asset: str
    url: str
    scan_id: UUID

    @classmethod
    def from_view(cls, view: FindingView) -> "FindingDetailResponse":
        finding = view.finding
        return cls(
            id=finding.id,
            title=finding.title,
            severity=finding.severity,
            priority_score=finding.priority_score,
            remediation_status=finding.remediation_status,
            status=view.lifecycle,
            is_false_positive=finding.is_false_positive,
            cve_ids=list(finding.cve_ids),
            detected_at=finding.detected_at,
            domain_id=view.domain_id,
            domain=view.domain_name,
            asset_id=view.asset_id,
            asset=view.asset_value,
            url=view.url,
            scan_id=view.scan_id,
        )


class FindingPageResponse(BaseModel):
    items: list[FindingDetailResponse]
    next_cursor: str | None

    @classmethod
    def from_page(cls, page: FindingPage) -> "FindingPageResponse":
        return cls(
            items=[FindingDetailResponse.from_view(v) for v in page.items],
            next_cursor=page.next_cursor,
        )


class FindingStatusRequest(BaseModel):
    status: RemediationStatus
    reason: str | None = Field(default=None, max_length=500)
