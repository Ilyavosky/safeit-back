from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.application.ports.reports import RecommendationLine, ReportDocument
from app.application.use_cases.reports.dashboard import DashboardSummary
from app.domain.entities.report import Recommendation
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.recommendation_status import RecommendationStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity
from app.interfaces.api.schemas.findings import FindingDetailResponse


class RecommendationResponse(BaseModel):
    id: UUID
    finding_id: UUID
    finding_title: str | None = None
    severity: Severity | None = None
    url: str | None = None
    priority: int
    action: str
    status: RecommendationStatus

    @classmethod
    def from_line(cls, line: RecommendationLine) -> "RecommendationResponse":
        return cls(
            id=line.id,
            finding_id=line.finding_id,
            finding_title=line.finding_title,
            severity=line.severity,
            url=line.url,
            priority=line.priority,
            action=line.action,
            status=line.status,
        )

    @classmethod
    def from_recommendation(cls, rec: Recommendation) -> "RecommendationResponse":
        return cls(
            id=rec.id,
            finding_id=rec.finding_id,
            priority=rec.priority,
            action=rec.action,
            status=rec.status,
        )


class ReportResponse(BaseModel):
    scan_id: UUID
    domain: str
    created_at: datetime
    summary: str
    total_findings: int
    severity_counts: dict[Severity, int]
    recommendations: list[RecommendationResponse]
    generated_with_llm: bool

    @classmethod
    def from_document(cls, document: ReportDocument) -> "ReportResponse":
        return cls(
            scan_id=document.scan_id,
            domain=document.domain,
            created_at=document.created_at,
            summary=document.summary,
            total_findings=document.total,
            severity_counts=document.counts,
            recommendations=[RecommendationResponse.from_line(r) for r in document.recommendations],
            generated_with_llm=document.generated_with_llm,
        )


class RecommendationStatusRequest(BaseModel):
    status: RecommendationStatus


class DashboardResponse(BaseModel):
    scan_id: UUID | None
    domain_id: UUID | None
    total_findings: int
    severity_counts: dict[Severity, int]
    remediation_counts: dict[RemediationStatus, int]
    assets: int
    scans: dict[JobStatus, int]
    latest_findings: list[FindingDetailResponse]

    @classmethod
    def from_summary(cls, summary: DashboardSummary) -> "DashboardResponse":
        return cls(
            scan_id=summary.scan_id,
            domain_id=summary.domain_id,
            total_findings=summary.total_findings,
            severity_counts=summary.severity_counts,
            remediation_counts=summary.remediation_counts,
            assets=summary.assets,
            scans=summary.scans,
            latest_findings=[FindingDetailResponse.from_view(v) for v in summary.latest_findings],
        )
