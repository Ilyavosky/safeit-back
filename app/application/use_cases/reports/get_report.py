from uuid import UUID

from app.application.ports.findings_query import FindingQueryRepository, Scope
from app.application.ports.reports import (
    RecommendationLine,
    ReportDocument,
    ReportRenderer,
    ReportRepository,
)
from app.application.ports.repositories import DomainRepository
from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.reports.access import load_scan
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError
from app.domain.services.report_builder import severity_counts


class GetReport:
    def __init__(
        self,
        domains: DomainRepository,
        scans: ScanRepository,
        reports: ReportRepository,
        findings: FindingQueryRepository,
    ) -> None:
        self._domains = domains
        self._scans = scans
        self._reports = reports
        self._findings = findings

    async def execute(self, user: User, scan_id: UUID) -> ReportDocument:
        _, domain = await load_scan(self._domains, self._scans, user, scan_id)
        report = await self._reports.get_by_scan(scan_id)
        if report is None:
            raise EntityNotFoundError("report", scan_id)
        counts = await self._findings.severity_counts(Scope(scan_id=scan_id))
        recommendations = await self._reports.list_recommendations(report.id)
        views = await self._findings.get_many([r.finding_id for r in recommendations])
        lines = [
            RecommendationLine(
                id=r.id,
                finding_id=r.finding_id,
                finding_title=views[r.finding_id].finding.title,
                severity=views[r.finding_id].finding.severity,
                url=views[r.finding_id].url,
                priority=r.priority,
                action=r.action,
                status=r.status,
            )
            for r in recommendations
            if r.finding_id in views
        ]
        return ReportDocument(
            scan_id=scan_id,
            domain=domain.name,
            created_at=report.created_at,
            summary=report.summary,
            counts={**severity_counts([]), **counts},
            recommendations=lines,
            generated_with_llm=report.decision_id is not None,
        )


class RenderReportPdf:
    def __init__(
        self, get_report: GetReport, renderer: ReportRenderer, audit: RecordAction
    ) -> None:
        self._get_report = get_report
        self._renderer = renderer
        self._audit = audit

    async def execute(self, user: User, scan_id: UUID) -> bytes:
        document = await self._get_report.execute(user, scan_id)
        pdf = self._renderer.render(document)
        await self._audit.execute(
            "report.pdf_downloaded",
            user_id=user.id,
            entity="scan",
            entity_id=scan_id,
            detail={"bytes": len(pdf)},
        )
        return pdf
