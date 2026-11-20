from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.cve import CveRecord
from app.infrastructure.db.cve_repository import PostgresCveRepository

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def _record(cve_id: str = "CVE-2021-44228", **changes: Any) -> CveRecord:
    base = CveRecord(
        cve_id=cve_id,
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        epss_score=0.94358,
        in_cisa_kev=True,
        synced_at=NOW,
    )
    return replace(base, **changes)


async def test_roundtrip_and_listing(migrated_pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresCveRepository(migrated_pool)
    a, b = _record(), _record("CVE-2014-0160", cvss_score=7.5, epss_score=None, in_cisa_kev=False)
    assert await repo.upsert_changed([a, b]) == 2
    assert await repo.get("CVE-2021-44228") == a
    assert await repo.get("CVE-2014-0160") == b
    assert await repo.get("CVE-2000-0001") is None
    assert [r.cve_id for r in await repo.list_all()] == ["CVE-2014-0160", "CVE-2021-44228"]
    found = await repo.get_many(["CVE-2014-0160", "CVE-2000-0001"])
    assert list(found) == ["CVE-2014-0160"]
    assert await repo.get_many([]) == {}


async def test_upsert_is_idempotent_and_keeps_synced_at(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    repo = PostgresCveRepository(migrated_pool)
    original = _record()
    assert await repo.upsert_changed([original]) == 1
    later = replace(original, synced_at=NOW + timedelta(hours=6))
    assert await repo.upsert_changed([later]) == 0
    stored = await repo.get(original.cve_id)
    assert stored is not None
    assert stored.synced_at == NOW


async def test_upsert_updates_only_rows_with_new_data(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    repo = PostgresCveRepository(migrated_pool)
    first, second = _record(), _record("CVE-2014-0160", cvss_score=7.5)
    await repo.upsert_changed([first, second])
    refreshed = NOW + timedelta(hours=6)
    batch = [
        replace(first, synced_at=refreshed),
        replace(second, epss_score=0.5, synced_at=refreshed),
    ]
    assert await repo.upsert_changed(batch) == 1
    stored_first = await repo.get(first.cve_id)
    stored_second = await repo.get(second.cve_id)
    assert stored_first is not None
    assert stored_second is not None
    assert stored_first.synced_at == NOW
    assert (stored_second.epss_score, stored_second.synced_at) == (0.5, refreshed)


async def test_rounded_values_do_not_look_like_changes(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    repo = PostgresCveRepository(migrated_pool)
    record = _record(epss_score=0.12346, cvss_score=7.5)
    await repo.upsert_changed([record])
    assert await repo.upsert_changed([record]) == 0
