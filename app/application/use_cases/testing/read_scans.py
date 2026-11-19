from uuid import UUID

from app.application.ports.repositories import DomainRepository
from app.application.ports.testing_repositories import (
    FindingRepository,
    ScanRepository,
    TestRunRepository,
)
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.finding import Finding
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError


class _ScanAccess:
    def __init__(self, domains: DomainRepository, scans: ScanRepository) -> None:
        self._domains = domains
        self._scans = scans

    async def load(self, user: User, scan_id: UUID) -> Scan:
        scan = await self._scans.get(scan_id)
        if scan is None:
            raise EntityNotFoundError("scan", scan_id)
        await load_domain(self._domains, user, scan.domain_id, owner_only=False)
        return scan


class GetScan:
    def __init__(self, domains: DomainRepository, scans: ScanRepository) -> None:
        self._access = _ScanAccess(domains, scans)

    async def execute(self, user: User, scan_id: UUID) -> Scan:
        return await self._access.load(user, scan_id)


class ListTestRuns:
    def __init__(
        self, domains: DomainRepository, scans: ScanRepository, test_runs: TestRunRepository
    ) -> None:
        self._access = _ScanAccess(domains, scans)
        self._test_runs = test_runs

    async def execute(self, user: User, scan_id: UUID) -> list[TestRun]:
        await self._access.load(user, scan_id)
        return await self._test_runs.list_by_scan(scan_id)


class ListScanFindings:
    def __init__(
        self, domains: DomainRepository, scans: ScanRepository, findings: FindingRepository
    ) -> None:
        self._access = _ScanAccess(domains, scans)
        self._findings = findings

    async def execute(self, user: User, scan_id: UUID) -> list[Finding]:
        await self._access.load(user, scan_id)
        return await self._findings.list_by_scan(scan_id)
