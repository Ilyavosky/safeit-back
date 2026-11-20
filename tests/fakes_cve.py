from collections.abc import AsyncIterator, Sequence
from dataclasses import replace

from app.application.ports.cve_catalog import NvdCve
from app.domain.entities.cve import CveRecord
from app.domain.errors import FeedUnavailableError


class InMemoryCveRepository:
    def __init__(self) -> None:
        self.records: dict[str, CveRecord] = {}

    async def get(self, cve_id: str) -> CveRecord | None:
        return self.records.get(cve_id)

    async def get_many(self, cve_ids: Sequence[str]) -> dict[str, CveRecord]:
        return {i: self.records[i] for i in cve_ids if i in self.records}

    async def list_all(self) -> list[CveRecord]:
        return sorted(self.records.values(), key=lambda r: r.cve_id)

    async def upsert_changed(self, records: Sequence[CveRecord]) -> int:
        changed = 0
        for record in records:
            current = self.records.get(record.cve_id)
            if current is not None and replace(current, synced_at=record.synced_at) == record:
                continue
            self.records[record.cve_id] = record
            changed += 1
        return changed


class FakeNvd:
    def __init__(self) -> None:
        self.kev_items: list[NvdCve] = []
        self.by_id: dict[str, NvdCve] = {}
        self.fail_kev = False
        self.fail_lookup = False
        self.lookups: list[str] = []

    async def iter_kev_cves(self) -> AsyncIterator[NvdCve]:
        if self.fail_kev:
            raise FeedUnavailableError
        for item in self.kev_items:
            yield item

    async def get_cve(self, cve_id: str) -> NvdCve | None:
        self.lookups.append(cve_id)
        if self.fail_lookup:
            raise FeedUnavailableError
        return self.by_id.get(cve_id)


class FakeEpss:
    def __init__(self) -> None:
        self.scores: dict[str, float] = {}
        self.fail = False

    async def get_scores(self, cve_ids: Sequence[str]) -> dict[str, float]:
        if self.fail:
            raise FeedUnavailableError
        return {i: self.scores[i] for i in cve_ids if i in self.scores}


class FakeKev:
    def __init__(self) -> None:
        self.ids: set[str] = set()
        self.fail = False

    async def list_cve_ids(self) -> set[str]:
        if self.fail:
            raise FeedUnavailableError
        return set(self.ids)
