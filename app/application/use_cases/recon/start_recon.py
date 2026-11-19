from datetime import timedelta
from uuid import UUID, uuid4

from app.application.ports.clock import Clock
from app.application.ports.recon import ReconQueue
from app.application.ports.recon_repositories import AssetRepository, ReconScanRepository
from app.application.ports.repositories import DomainRepository
from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.scan import Scan
from app.domain.entities.user import User
from app.domain.errors import ConflictError, DomainNotVerifiedError, EntityNotFoundError
from app.domain.errors_queue import QueueUnavailableError
from app.domain.value_objects.asset_kind import AssetKind
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType


class StartReconScan:
    def __init__(
        self,
        domains: DomainRepository,
        scans: ScanRepository,
        recon_scans: ReconScanRepository,
        queue: ReconQueue,
        audit: RecordAction,
        clock: Clock,
        stale_after_seconds: int,
    ) -> None:
        self._domains = domains
        self._scans = scans
        self._recon_scans = recon_scans
        self._queue = queue
        self._audit = audit
        self._clock = clock
        self._stale_after = timedelta(seconds=stale_after_seconds)

    async def execute(self, user: User, domain_id: UUID, only_host: str | None = None) -> Scan:
        domain = await load_domain(self._domains, user, domain_id, owner_only=False)
        if not domain.is_verified:
            raise DomainNotVerifiedError
        now = self._clock.now()
        await self._recon_scans.fail_stale(domain.id, now - self._stale_after)
        scan = Scan(
            id=uuid4(),
            domain_id=domain.id,
            started_by=user.id,
            type=ScanType.RECON,
            status=JobStatus.QUEUED,
            created_at=now,
        )
        if not await self._recon_scans.add_if_idle(scan):
            raise ConflictError("Ya hay un escaneo de reconocimiento activo para este dominio.")
        await self._audit.execute(
            "scan.recon_started",
            user_id=user.id,
            entity="scan",
            entity_id=scan.id,
            detail={"domain": domain.name, "host": only_host},
        )
        try:
            await self._queue.enqueue(scan.id, only_host)
        except QueueUnavailableError:
            failed = scan.finish(JobStatus.FAILED, self._clock.now())
            await self._scans.save(failed)
            await self._audit.execute(
                "scan.recon_finished",
                user_id=user.id,
                entity="scan",
                entity_id=scan.id,
                detail={"status": "failed", "reason": "queue_unavailable"},
            )
            raise
        return scan


class RescanAsset:
    def __init__(
        self, domains: DomainRepository, assets: AssetRepository, start: StartReconScan
    ) -> None:
        self._domains = domains
        self._assets = assets
        self._start = start

    async def execute(self, user: User, asset_id: UUID) -> Scan:
        asset = await self._assets.get(asset_id)
        if asset is None:
            raise EntityNotFoundError("asset", asset_id)
        await load_domain(self._domains, user, asset.domain_id, owner_only=False)
        if asset.kind is not AssetKind.SUBDOMAIN or not asset.in_scope:
            raise ConflictError("Solo se puede volver a escanear un subdominio en alcance.")
        return await self._start.execute(user, asset.domain_id, only_host=asset.value)
