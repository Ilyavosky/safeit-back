from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Protocol

from app.domain.entities.cve import CveRecord


@dataclass(frozen=True)
class NvdCve:
    cve_id: str
    cvss_score: float | None
    cvss_vector: str | None


class CveRepository(Protocol):
    async def get(self, cve_id: str) -> CveRecord | None: ...

    async def get_many(self, cve_ids: Sequence[str]) -> dict[str, CveRecord]: ...

    async def list_all(self) -> list[CveRecord]: ...

    async def upsert_changed(self, records: Sequence[CveRecord]) -> int: ...


class NvdFeed(Protocol):
    def iter_kev_cves(self) -> AsyncIterator[NvdCve]: ...

    async def get_cve(self, cve_id: str) -> NvdCve | None: ...


class EpssFeed(Protocol):
    async def get_scores(self, cve_ids: Sequence[str]) -> dict[str, float]: ...


class KevFeed(Protocol):
    async def list_cve_ids(self) -> set[str]: ...
