from dataclasses import replace
from uuid import UUID

from app.application.pagination import decode_cursor, encode_cursor
from app.application.ports.findings_query import (
    FindingFilter,
    FindingPage,
    FindingSort,
    FindingView,
    ReportSummary,
    Scope,
)
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.scan_type import ScanType
from app.domain.value_objects.severity import Severity
from tests.fakes import InMemoryDomainRepository
from tests.fakes_llm import InMemoryReportRepository
from tests.fakes_testing import (
    InMemoryEndpointRepository,
    InMemoryFindingRepository,
    InMemoryScanRepository,
    InMemoryTestRunRepository,
)


class InMemoryFindingQueryRepository:
    def __init__(
        self,
        findings: InMemoryFindingRepository,
        test_runs: InMemoryTestRunRepository,
        scans: InMemoryScanRepository,
        endpoints: InMemoryEndpointRepository,
        domains: InMemoryDomainRepository,
        reports: InMemoryReportRepository,
    ) -> None:
        self._findings = findings
        self._runs = test_runs
        self._scans = scans
        self._endpoints = endpoints
        self._domains = domains
        self._reports = reports
        self.in_scope_assets = 0

    def _views(self) -> list[FindingView]:
        views: list[FindingView] = []
        endpoints = {e.id: e for e in self._endpoints.endpoints}
        report_scans = {r.scan_id for r in self._reports.reports.values()}
        for finding in self._findings.findings:
            run = self._runs.runs.get(finding.test_run_id)
            endpoint = endpoints.get(finding.endpoint_id)
            if run is None or endpoint is None:
                continue
            scan = self._scans.scans[run.scan_id]
            domain = self._domains.domains[endpoint.domain_id]
            views.append(
                FindingView(
                    finding=finding,
                    domain_id=domain.id,
                    domain_name=domain.name,
                    asset_id=endpoint.asset_id,
                    asset_value=domain.name,
                    url=endpoint.url,
                    scan_id=scan.id,
                    scan_status=scan.status,
                    has_report=scan.id in report_scans,
                )
            )
        return views

    def _scoped(self, scope: Scope, *, include_false_positives: bool = False) -> list[FindingView]:
        views = self._views()
        latest: dict[UUID, UUID] = {}
        for scan in sorted(self._scans.scans.values(), key=lambda s: s.created_at):
            if scan.type is ScanType.TESTS and scan.status is JobStatus.DONE:
                latest[scan.domain_id] = scan.id
        result = []
        for v in views:
            if v.finding.is_false_positive and not include_false_positives:
                continue
            if (
                scope.owner_id is not None
                and self._domains.domains[v.domain_id].user_id != scope.owner_id
            ):
                continue
            if scope.domain_id is not None and v.domain_id != scope.domain_id:
                continue
            if scope.scan_id is not None:
                if v.scan_id != scope.scan_id:
                    continue
            elif latest.get(v.domain_id) != v.scan_id:
                continue
            result.append(v)
        return result

    async def latest_report_scan_id(self, owner_id: UUID | None) -> UUID | None:
        for report in sorted(
            self._reports.reports.values(), key=lambda r: (r.created_at, str(r.id)), reverse=True
        ):
            scan = self._scans.scans[report.scan_id]
            if owner_id is None or self._domains.domains[scan.domain_id].user_id == owner_id:
                return report.scan_id
        return None

    async def list_reports(self, owner_id: UUID | None, limit: int) -> list[ReportSummary]:
        summaries: list[ReportSummary] = []
        ordered = sorted(
            self._reports.reports.values(), key=lambda r: (r.created_at, str(r.id)), reverse=True
        )
        for report in ordered:
            scan = self._scans.scans[report.scan_id]
            domain = self._domains.domains[scan.domain_id]
            if owner_id is not None and domain.user_id != owner_id:
                continue
            counts: dict[Severity, int] = {}
            for view in self._scoped(Scope(scan_id=report.scan_id)):
                counts[view.finding.severity] = counts.get(view.finding.severity, 0) + 1
            summaries.append(
                ReportSummary(
                    report.scan_id,
                    domain.id,
                    domain.name,
                    report.created_at,
                    report.decision_id is not None,
                    counts,
                )
            )
        return summaries[:limit]

    async def get(self, finding_id: UUID) -> FindingView | None:
        return next((v for v in self._views() if v.finding.id == finding_id), None)

    async def get_many(self, finding_ids: list[UUID]) -> dict[UUID, FindingView]:
        wanted = set(finding_ids)
        return {v.finding.id: v for v in self._views() if v.finding.id in wanted}

    async def list_page(
        self,
        owner_id: UUID | None,
        filters: FindingFilter,
        sort: FindingSort,
        cursor: str | None,
        limit: int,
    ) -> FindingPage:
        items = []
        for v in self._views():
            if owner_id is not None and self._domains.domains[v.domain_id].user_id != owner_id:
                continue
            if filters.lifecycle is None and v.finding.is_false_positive:
                continue
            if filters.lifecycle is not None and v.lifecycle is not filters.lifecycle:
                continue
            if filters.severity is not None and v.finding.severity is not filters.severity:
                continue
            if filters.asset_id is not None and v.asset_id != filters.asset_id:
                continue
            if filters.domain_id is not None and v.domain_id != filters.domain_id:
                continue
            if filters.scan_id is not None and v.scan_id != filters.scan_id:
                continue
            items.append(v)

        def key(v: FindingView) -> str:
            if sort is FindingSort.PRIORITY:
                score = v.finding.priority_score
                return f"{score if score is not None else -1.0:012.3f}"
            return v.finding.detected_at.isoformat()

        items.sort(key=lambda v: (key(v), str(v.finding.id)), reverse=True)
        if cursor is not None:
            last_key, last_id = decode_cursor(cursor)
            items = [v for v in items if (key(v), str(v.finding.id)) < (last_key, str(last_id))]
        page = items[:limit]
        next_cursor = None
        if len(items) > limit:
            next_cursor = encode_cursor(key(page[-1]), page[-1].finding.id)
        return FindingPage(page, next_cursor)

    async def set_remediation(self, finding_id: UUID, status: RemediationStatus) -> None:
        for index, finding in enumerate(self._findings.findings):
            if finding.id == finding_id:
                self._findings.findings[index] = replace(finding, remediation_status=status)

    async def severity_counts(self, scope: Scope) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for v in self._scoped(scope):
            counts[v.finding.severity] = counts.get(v.finding.severity, 0) + 1
        return counts

    async def remediation_counts(self, scope: Scope) -> dict[RemediationStatus, int]:
        counts: dict[RemediationStatus, int] = {}
        for v in self._scoped(scope):
            status = v.finding.remediation_status
            counts[status] = counts.get(status, 0) + 1
        return counts

    async def latest(self, scope: Scope, limit: int) -> list[FindingView]:
        views = self._scoped(scope)
        views.sort(key=lambda v: (v.finding.detected_at, str(v.finding.id)), reverse=True)
        return views[:limit]

    async def asset_count(self, scope: Scope) -> int:
        return self.in_scope_assets

    async def scan_status_counts(self, scope: Scope) -> dict[JobStatus, int]:
        counts: dict[JobStatus, int] = {}
        for scan in self._scans.scans.values():
            domain = self._domains.domains[scan.domain_id]
            if scope.owner_id is not None and domain.user_id != scope.owner_id:
                continue
            if scope.domain_id is not None and domain.id != scope.domain_id:
                continue
            if scope.scan_id is not None and scan.id != scope.scan_id:
                continue
            counts[scan.status] = counts.get(scan.status, 0) + 1
        return counts
