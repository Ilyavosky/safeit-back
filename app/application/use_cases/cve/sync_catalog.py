from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

import structlog

from app.application.ports.clock import Clock
from app.application.ports.cve_catalog import CveRepository, EpssFeed, KevFeed, NvdCve, NvdFeed
from app.domain.entities.cve import CveRecord
from app.domain.errors import FeedUnavailableError
from app.domain.services.cve_id import normalize_cve_id

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class SyncResult:
    targets: int
    changed: int
    kev_ok: bool
    nvd_ok: bool
    epss_ok: bool
    lookups_skipped: int

    @property
    def complete(self) -> bool:
        return self.kev_ok and self.nvd_ok and self.epss_ok


class SyncCveCatalog:
    def __init__(
        self,
        repository: CveRepository,
        nvd: NvdFeed,
        epss: EpssFeed,
        kev: KevFeed,
        clock: Clock,
        max_lookups: int = 200,
    ) -> None:
        self._repository = repository
        self._nvd = nvd
        self._epss = epss
        self._kev = kev
        self._clock = clock
        self._max_lookups = max_lookups

    async def execute(self, extra_ids: Iterable[str] = ()) -> SyncResult:
        existing = {record.cve_id: record for record in await self._repository.list_all()}
        requested = {normalize_cve_id(raw) for raw in extra_ids}

        kev_ids = await self._load_kev()
        nvd_data: dict[str, NvdCve] = {}
        nvd_ok = await self._load_kev_cves(nvd_data)

        pending = self._pending_lookups(requested, kev_ids, existing, nvd_data)
        skipped = max(0, len(pending) - self._max_lookups)
        if nvd_ok:
            nvd_ok = await self._lookup(pending[: self._max_lookups], nvd_data)
        if skipped:
            log.warning("cve_sync_lookups_skipped", skipped=skipped, limit=self._max_lookups)

        targets = sorted(set(existing) | set(nvd_data) | requested | (kev_ids or set()))
        scores, epss_ok = await self._load_epss(targets)

        now = self._clock.now()
        records: list[CveRecord] = []
        for cve_id in targets:
            record = _merge(
                cve_id, existing.get(cve_id), nvd_data.get(cve_id), scores, kev_ids, now
            )
            if record is not None:
                records.append(record)
        changed = await self._repository.upsert_changed(records)
        return SyncResult(
            targets=len(targets),
            changed=changed,
            kev_ok=kev_ids is not None,
            nvd_ok=nvd_ok,
            epss_ok=epss_ok,
            lookups_skipped=skipped,
        )

    async def _load_kev(self) -> set[str] | None:
        try:
            return await self._kev.list_cve_ids()
        except FeedUnavailableError as exc:
            log.warning("cve_sync_kev_unavailable", reason=exc.message)
            return None

    async def _load_kev_cves(self, into: dict[str, NvdCve]) -> bool:
        try:
            async for item in self._nvd.iter_kev_cves():
                into[item.cve_id] = item
        except FeedUnavailableError as exc:
            log.warning("cve_sync_nvd_unavailable", stage="kev", reason=exc.message)
            return False
        return True

    async def _lookup(self, cve_ids: list[str], into: dict[str, NvdCve]) -> bool:
        for cve_id in cve_ids:
            try:
                item = await self._nvd.get_cve(cve_id)
            except FeedUnavailableError as exc:
                log.warning("cve_sync_nvd_unavailable", stage="lookup", reason=exc.message)
                return False
            if item is not None:
                into[cve_id] = item
        return True

    async def _load_epss(self, targets: list[str]) -> tuple[dict[str, float], bool]:
        if not targets:
            return {}, True
        try:
            return await self._epss.get_scores(targets), True
        except FeedUnavailableError as exc:
            log.warning("cve_sync_epss_unavailable", reason=exc.message)
            return {}, False

    @staticmethod
    def _pending_lookups(
        requested: set[str],
        kev_ids: set[str] | None,
        existing: dict[str, CveRecord],
        nvd_data: dict[str, NvdCve],
    ) -> list[str]:
        wanted = set(requested) | (kev_ids or set())
        wanted |= {cve_id for cve_id, record in existing.items() if record.cvss_score is None}
        return sorted(wanted - set(nvd_data))


def _merge(
    cve_id: str,
    existing: CveRecord | None,
    nvd: NvdCve | None,
    scores: dict[str, float],
    kev_ids: set[str] | None,
    now: datetime,
) -> CveRecord | None:
    cvss_score = existing.cvss_score if existing else None
    cvss_vector = existing.cvss_vector if existing else None
    if nvd is not None and nvd.cvss_score is not None:
        cvss_score, cvss_vector = nvd.cvss_score, nvd.cvss_vector
    epss_score = scores.get(cve_id, existing.epss_score if existing else None)
    if kev_ids is not None:
        in_kev = cve_id in kev_ids
    else:
        in_kev = existing.in_cisa_kev if existing else False
    if existing is None and cvss_score is None and epss_score is None and not in_kev:
        return None
    return CveRecord(
        cve_id=cve_id,
        cvss_score=None if cvss_score is None else round(cvss_score, 1),
        cvss_vector=cvss_vector,
        epss_score=None if epss_score is None else round(epss_score, 5),
        in_cisa_kev=in_kev,
        synced_at=now,
    )
