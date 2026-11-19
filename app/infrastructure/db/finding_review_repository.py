from collections.abc import Sequence
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.application.ports.llm import ReviewItem
from app.domain.entities.finding import Finding
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity


class PostgresFindingReviewRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def list_for_review(self, scan_id: UUID) -> list[ReviewItem]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select f.id, f.test_run_id, f.endpoint_id, f.title, f.severity, f.priority_score, "
                "f.remediation_status, f.detected_at, f.is_false_positive, "
                "coalesce((select array_agg(fc.cve_id order by fc.cve_id) "
                "from public.finding_cves fc where fc.finding_id = f.id), '{}'), "
                "t.name, e.url, f.evidence_enc "
                "from public.findings f "
                "join public.test_runs r on r.id = f.test_run_id "
                "join public.allowed_tools t on t.id = r.tool_id "
                "join public.endpoints e on e.id = f.endpoint_id "
                "where r.scan_id = %s and not f.is_false_positive "
                "order by f.priority_score desc nulls last, f.id",
                (scan_id,),
            )
            rows = await cursor.fetchall()
        return [
            ReviewItem(
                finding=Finding(
                    id=r[0],
                    test_run_id=r[1],
                    endpoint_id=r[2],
                    title=r[3],
                    severity=Severity(r[4]),
                    priority_score=float(r[5]) if r[5] is not None else None,
                    remediation_status=RemediationStatus(r[6]),
                    detected_at=r[7],
                    is_false_positive=r[8],
                    cve_ids=tuple(r[9]),
                ),
                tool_name=r[10],
                url=r[11],
                evidence_enc=bytes(r[12]) if r[12] is not None else None,
            )
            for r in rows
        ]

    async def attach_cves(
        self, finding_id: UUID, cve_ids: Sequence[str], priority: float | None
    ) -> None:
        async with self._pool.connection() as conn, conn.transaction():
            for cve_id in cve_ids:
                await conn.execute(
                    "insert into public.finding_cves (finding_id, cve_id) values (%s, %s) "
                    "on conflict do nothing",
                    (finding_id, cve_id),
                )
            await conn.execute(
                "update public.findings set priority_score = %s where id = %s",
                (priority, finding_id),
            )

    async def mark_false_positive(
        self, finding_id: UUID, justification: str, decision_id: UUID
    ) -> None:
        async with self._pool.connection() as conn:
            await conn.execute(
                "update public.findings set is_false_positive = true, fp_justification = %s, "
                "decision_id = %s where id = %s",
                (justification, decision_id, finding_id),
            )
