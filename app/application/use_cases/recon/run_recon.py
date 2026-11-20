import asyncio
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import structlog

from app.application.ports.clock import Clock
from app.application.ports.recon import HostResolver, HttpProber, PortScanner, SubdomainEnumerator
from app.application.ports.recon_repositories import AssetRepository
from app.application.ports.repositories import DomainRepository
from app.application.ports.testing import ToolExecutionError
from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.domain.entities.asset import Asset
from app.domain.entities.domain import Domain
from app.domain.entities.scan import Scan
from app.domain.errors import OutOfScopeError
from app.domain.services.recon_scope import discard_reason, normalize_host
from app.domain.services.scope_policy import ensure_url_in_scope, is_host_in_domain
from app.domain.value_objects.asset_kind import AssetKind
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType

log = structlog.get_logger(__name__)

MAX_AUDITED_DISCARDS = 50


@dataclass(frozen=True)
class ReconLimits:
    max_assets: int
    timeout_seconds: int


@dataclass
class _Summary:
    hosts: dict[str, Asset] = field(default_factory=dict)
    ips: dict[str, Asset] = field(default_factory=dict)
    services: int = 0
    endpoints: int = 0
    discarded: int = 0
    unresolved: int = 0
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)


class _Aborted(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class RunReconScan:
    def __init__(
        self,
        *,
        domains: DomainRepository,
        scans: ScanRepository,
        assets: AssetRepository,
        enumerator: SubdomainEnumerator,
        resolver: HostResolver,
        scanner: PortScanner,
        prober: HttpProber,
        audit: RecordAction,
        clock: Clock,
        limits: ReconLimits,
    ) -> None:
        self._domains = domains
        self._scans = scans
        self._assets = assets
        self._enumerator = enumerator
        self._resolver = resolver
        self._scanner = scanner
        self._prober = prober
        self._audit = audit
        self._clock = clock
        self._limits = limits

    async def execute(self, scan_id: UUID, only_host: str | None = None) -> Scan | None:
        scan = await self._scans.get(scan_id)
        if scan is None or scan.type is not ScanType.RECON or scan.status is not JobStatus.QUEUED:
            return None
        scan = scan.start(self._clock.now())
        await self._scans.save(scan)
        summary = _Summary()
        reason: str | None = None
        try:
            async with asyncio.timeout(self._limits.timeout_seconds):
                await self._discover(scan, only_host, summary)
        except TimeoutError:
            reason = "timeout"
        except _Aborted as exc:
            reason = exc.reason
        except Exception:
            log.exception("recon_failed", scan_id=str(scan.id))
            reason = "error"
        status = JobStatus.FAILED if reason else JobStatus.DONE
        finished = scan.finish(status, self._clock.now())
        await self._scans.save(finished)
        await self._audit.execute(
            "scan.recon_finished",
            user_id=scan.started_by,
            entity="scan",
            entity_id=scan.id,
            detail={
                "status": status.value,
                "reason": reason,
                "assets": len(summary.hosts) + len(summary.ips),
                "services": summary.services,
                "endpoints": summary.endpoints,
                "discarded": summary.discarded,
                "unresolved": summary.unresolved,
                "truncated": summary.truncated,
                "warnings": summary.warnings,
            },
        )
        return finished

    async def _discover(self, scan: Scan, only_host: str | None, summary: _Summary) -> None:
        domain = await self._domains.get_by_id(scan.domain_id)
        if domain is None or not domain.is_verified:
            raise _Aborted("domain_not_verified")
        for host in await self._candidate_hosts(domain, only_host, summary):
            if len(summary.hosts) + len(summary.ips) >= self._limits.max_assets:
                summary.truncated = True
                break
            await self._register_host(scan, domain, host, summary)
        await self._scan_ports(summary)
        await self._probe_http(domain, summary)

    async def _candidate_hosts(
        self, domain: Domain, only_host: str | None, summary: _Summary
    ) -> list[str]:
        if only_host is not None:
            raw = [only_host]
        else:
            raw = [domain.name]
            try:
                raw.extend(await self._enumerator.enumerate(domain.name))
            except ToolExecutionError as exc:
                summary.warnings.append(f"subdominios: {exc}")
        hosts: dict[str, None] = {}
        for item in raw:
            host = normalize_host(item)
            if host is None or not is_host_in_domain(host, domain.name):
                await self._discard(domain, item[:255], "outside_domain", summary)
                continue
            hosts[host] = None
        return list(hosts)

    async def _register_host(
        self, scan: Scan, domain: Domain, host: str, summary: _Summary
    ) -> None:
        addresses = await self._resolver.resolve(host)
        reason = discard_reason(addresses)
        if reason == "unresolved":
            summary.unresolved += 1
            return
        if reason is not None:
            await self._discard(domain, host, reason, summary, scan.started_by)
            return
        now = self._clock.now()
        summary.hosts[host] = await self._assets.upsert(
            Asset(uuid4(), domain.id, scan.id, AssetKind.SUBDOMAIN, host, True, now)
        )
        for address in addresses:
            if address not in summary.ips:
                summary.ips[address] = await self._assets.upsert(
                    Asset(uuid4(), domain.id, scan.id, AssetKind.IP, address, True, now)
                )

    async def _scan_ports(self, summary: _Summary) -> None:
        if not summary.ips:
            return
        try:
            found = await self._scanner.scan(list(summary.ips))
        except ToolExecutionError as exc:
            summary.warnings.append(f"puertos: {exc}")
            return
        for address, services in found.items():
            asset = summary.ips.get(address)
            if asset is None:
                continue
            await self._assets.replace_services(asset.id, services)
            summary.services += len(services)

    async def _probe_http(self, domain: Domain, summary: _Summary) -> None:
        if not summary.hosts:
            return
        try:
            probes = await self._prober.probe(list(summary.hosts))
        except ToolExecutionError as exc:
            summary.warnings.append(f"http: {exc}")
            return
        for probe in probes:
            asset = summary.hosts.get(probe.host)
            try:
                ensure_url_in_scope(probe.url, domain.name)
            except OutOfScopeError:
                asset = None
            if asset is None:
                await self._discard(domain, probe.url[:255], "endpoint_out_of_scope", summary)
                continue
            await self._assets.upsert_endpoint(asset.id, probe)
            summary.endpoints += 1

    async def _discard(
        self,
        domain: Domain,
        target: str,
        reason: str,
        summary: _Summary,
        user_id: UUID | None = None,
    ) -> None:
        summary.discarded += 1
        if summary.discarded > MAX_AUDITED_DISCARDS:
            return
        await self._audit.execute(
            "recon.asset_discarded",
            user_id=user_id or domain.user_id,
            entity="domain",
            entity_id=domain.id,
            detail={"target": target, "reason": reason},
        )
