from collections.abc import Sequence
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.application.ports.reports import RecommendationRef
from app.domain.entities.report import Recommendation, Report
from app.domain.value_objects.recommendation_status import RecommendationStatus

_REC_COLUMNS = "id, report_id, finding_id, priority, action, status"


def _rec(row: Sequence[Any]) -> Recommendation:
    return Recommendation(
        id=row[0],
        report_id=row[1],
        finding_id=row[2],
        priority=row[3],
        action=row[4],
        status=RecommendationStatus(row[5]),
    )


class PostgresReportRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def get_by_scan(self, scan_id: UUID) -> Report | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select id, scan_id, decision_id, summary, content, created_at "
                "from public.reports where scan_id = %s",
                (scan_id,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return Report(row[0], row[1], row[2], row[3], row[4], row[5])

    async def add(self, report: Report, recommendations: Sequence[Recommendation]) -> None:
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute(
                "insert into public.reports (id, scan_id, decision_id, summary, content, "
                "created_at) values (%s, %s, %s, %s, %s, %s)",
                (
                    report.id,
                    report.scan_id,
                    report.decision_id,
                    report.summary,
                    report.content,
                    report.created_at,
                ),
            )
            for rec in recommendations:
                await conn.execute(
                    "insert into public.recommendations "
                    "(id, report_id, finding_id, priority, action, status) "
                    "values (%s, %s, %s, %s, %s, %s)",
                    (
                        rec.id,
                        rec.report_id,
                        rec.finding_id,
                        rec.priority,
                        rec.action,
                        rec.status.value,
                    ),
                )

    async def list_recommendations(self, report_id: UUID) -> list[Recommendation]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                f"select {_REC_COLUMNS} from public.recommendations "
                "where report_id = %s order by priority, id",
                (report_id,),
            )
            rows = await cursor.fetchall()
        return [_rec(r) for r in rows]

    async def get_recommendation(self, recommendation_id: UUID) -> RecommendationRef | None:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select r.id, r.report_id, r.finding_id, r.priority, r.action, r.status, "
                "p.scan_id from public.recommendations r "
                "join public.reports p on p.id = r.report_id where r.id = %s",
                (recommendation_id,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        return RecommendationRef(_rec(row), row[6])

    async def set_recommendation_status(
        self, recommendation_id: UUID, status: RecommendationStatus
    ) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.recommendations set status = %s where id = %s",
                (status.value, recommendation_id),
            )
