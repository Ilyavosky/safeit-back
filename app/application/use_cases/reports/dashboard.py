from dataclasses import dataclass
from uuid import UUID

from app.application.ports.findings_query import FindingQueryRepository, FindingView, Scope
from app.application.ports.repositories import DomainRepository
from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.domains.access import load_domain
from app.application.use_cases.reports.access import load_scan
from app.domain.entities.user import User
from app.domain.services.report_builder import SEVERITY_ORDER
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.role import Role
from app.domain.value_objects.severity import Severity

LATEST_FINDINGS = 5


@dataclass(frozen=True)
class DashboardSummary:
    severity_counts: dict[Severity, int]
    total_findings: int
    remediation_counts: dict[RemediationStatus, int]
    assets: int
    scans: dict[JobStatus, int]
    latest_findings: list[FindingView]
    scan_id: UUID | None
    domain_id: UUID | None


class GetDashboardSummary:
    def __init__(
        self, domains: DomainRepository, scans: ScanRepository, findings: FindingQueryRepository
    ) -> None:
        self._domains = domains
        self._scans = scans
        self._findings = findings

    async def execute(
        self, user: User, *, domain_id: UUID | None = None, scan_id: UUID | None = None
    ) -> DashboardSummary:
        if scan_id is not None:
            scan, _ = await load_scan(self._domains, self._scans, user, scan_id)
            domain_id = scan.domain_id
        elif domain_id is not None:
            await load_domain(self._domains, user, domain_id, owner_only=False)
        owner_id = None if user.role is Role.ADMIN else user.id
        scope = Scope(owner_id=owner_id, domain_id=domain_id, scan_id=scan_id)
        counts = await self._findings.severity_counts(scope)
        severity = {s: counts.get(s, 0) for s in SEVERITY_ORDER}
        remediation = await self._findings.remediation_counts(scope)
        scan_counts = await self._findings.scan_status_counts(scope)
        return DashboardSummary(
            severity_counts=severity,
            total_findings=sum(severity.values()),
            remediation_counts={s: remediation.get(s, 0) for s in RemediationStatus},
            assets=await self._findings.asset_count(scope),
            scans={s: scan_counts.get(s, 0) for s in JobStatus},
            latest_findings=await self._findings.latest(scope, LATEST_FINDINGS),
            scan_id=scan_id,
            domain_id=domain_id,
        )
