from collections.abc import Sequence
from typing import Any

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.cve import CveRecord
from app.infrastructure.db.sql_builder import query

_COLUMNS = "cve_id, cvss_score, cvss_vector, epss_score, in_cisa_kev, synced_at"

_UPSERT = query(
    "insert into public.cve_catalog ({columns}) values (%s, %s, %s, %s, %s, %s) on conflict "
    "(cve_id) do update set cvss_score = excluded.cvss_score, cvss_vector = "
    "excluded.cvss_vector, epss_score = excluded.epss_score, in_cisa_kev = "
    "excluded.in_cisa_kev, synced_at = excluded.synced_at where "
    "(public.cve_catalog.cvss_score, public.cve_catalog.cvss_vector, "
    "public.cve_catalog.epss_score, public.cve_catalog.in_cisa_kev) is distinct from "
    "(excluded.cvss_score, excluded.cvss_vector, excluded.epss_score, excluded.in_cisa_kev)",
    columns=_COLUMNS,
)


def _to_record(row: tuple[Any, ...]) -> CveRecord:
    return CveRecord(
        cve_id=row[0],
        cvss_score=None if row[1] is None else float(row[1]),
        cvss_vector=row[2],
        epss_score=None if row[3] is None else float(row[3]),
        in_cisa_kev=row[4],
        synced_at=row[5],
    )


class PostgresCveRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def get(self, cve_id: str) -> CveRecord | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {columns} from public.cve_catalog where cve_id = %s", columns=_COLUMNS
                ),
                (cve_id,),
            )
            row = await cursor.fetchone()
        return None if row is None else _to_record(row)

    async def get_many(self, cve_ids: Sequence[str]) -> dict[str, CveRecord]:
        if not cve_ids:
            return {}
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query(
                    "select {columns} from public.cve_catalog where cve_id = any(%s)",
                    columns=_COLUMNS,
                ),
                (list(cve_ids),),
            )
            rows = await cursor.fetchall()
        return {record.cve_id: record for record in map(_to_record, rows)}

    async def list_all(self) -> list[CveRecord]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                query("select {columns} from public.cve_catalog order by cve_id", columns=_COLUMNS)
            )
            rows = await cursor.fetchall()
        return [_to_record(row) for row in rows]

    async def upsert_changed(self, records: Sequence[CveRecord]) -> int:
        changed = 0
        async with self._pool.connection() as conn, conn.transaction():
            for record in records:
                cursor = await conn.execute(
                    _UPSERT,
                    (
                        record.cve_id,
                        record.cvss_score,
                        record.cvss_vector,
                        record.epss_score,
                        record.in_cisa_kev,
                        record.synced_at,
                    ),
                )
                changed += cursor.rowcount
        return changed
