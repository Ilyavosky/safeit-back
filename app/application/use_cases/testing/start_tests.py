from uuid import UUID, uuid4

from app.application.ports.clock import Clock
from app.application.ports.repositories import DomainRepository
from app.application.ports.testing import ScanScheduler
from app.application.ports.testing_repositories import EndpointRepository, ScanRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.domains.access import load_domain
from app.application.use_cases.testing.run_scan_tests import RunScanTests
from app.domain.entities.scan import Scan
from app.domain.entities.user import User
from app.domain.errors import ConflictError, DomainNotVerifiedError
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType


class StartTests:
    def __init__(
        self,
        domains: DomainRepository,
        endpoints: EndpointRepository,
        scans: ScanRepository,
        runner: RunScanTests,
        scheduler: ScanScheduler,
        audit: RecordAction,
        clock: Clock,
    ) -> None:
        self._domains = domains
        self._endpoints = endpoints
        self._scans = scans
        self._runner = runner
        self._scheduler = scheduler
        self._audit = audit
        self._clock = clock

    async def execute(self, user: User, domain_id: UUID) -> Scan:
        domain = await load_domain(self._domains, user, domain_id, owner_only=False)
        if not domain.is_verified:
            raise DomainNotVerifiedError
        if not await self._endpoints.list_testable(domain.id):
            raise ConflictError(
                "El dominio no tiene endpoints en alcance y en lista blanca para probar."
            )
        scan = Scan(
            id=uuid4(),
            domain_id=domain.id,
            started_by=user.id,
            type=ScanType.TESTS,
            status=JobStatus.QUEUED,
            created_at=self._clock.now(),
        )
        await self._scans.add(scan)
        await self._audit.execute(
            "scan.tests_started",
            user_id=user.id,
            entity="scan",
            entity_id=scan.id,
            detail={"domain": domain.name},
        )
        scan_id = scan.id

        async def job() -> None:
            await self._runner.execute(scan_id)

        self._scheduler.schedule(job)
        return scan
