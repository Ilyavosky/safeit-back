import structlog

from app.application.ports.clock import Clock
from app.application.ports.cve_catalog import CveRepository, EpssFeed, KevFeed, NvdFeed
from app.domain.entities.cve import CveRecord
from app.domain.errors import EntityNotFoundError, FeedUnavailableError
from app.domain.services.cve_id import normalize_cve_id

log = structlog.get_logger(__name__)


class LookupCve:
    def __init__(
        self,
        repository: CveRepository,
        nvd: NvdFeed,
        epss: EpssFeed,
        kev: KevFeed,
        clock: Clock,
    ) -> None:
        self._repository = repository
        self._nvd = nvd
        self._epss = epss
        self._kev = kev
        self._clock = clock

    async def execute(self, raw_id: str) -> CveRecord:
        cve_id = normalize_cve_id(raw_id)
        stored = await self._repository.get(cve_id)
        if stored is not None:
            return stored
        found = await self._nvd.get_cve(cve_id)
        if found is None:
            raise EntityNotFoundError("cve", cve_id)
        record = CveRecord(
            cve_id=cve_id,
            cvss_score=None if found.cvss_score is None else round(found.cvss_score, 1),
            cvss_vector=found.cvss_vector,
            epss_score=await self._epss_score(cve_id),
            in_cisa_kev=await self._in_kev(cve_id),
            synced_at=self._clock.now(),
        )
        await self._repository.upsert_changed([record])
        return record

    async def _epss_score(self, cve_id: str) -> float | None:
        try:
            scores = await self._epss.get_scores([cve_id])
        except FeedUnavailableError as exc:
            log.warning("cve_lookup_epss_unavailable", cve_id=cve_id, reason=exc.message)
            return None
        score = scores.get(cve_id)
        return None if score is None else round(score, 5)

    async def _in_kev(self, cve_id: str) -> bool:
        try:
            return cve_id in await self._kev.list_cve_ids()
        except FeedUnavailableError as exc:
            log.warning("cve_lookup_kev_unavailable", cve_id=cve_id, reason=exc.message)
            return False
