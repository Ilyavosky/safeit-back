from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from app.domain.entities.finding import Finding
from app.domain.value_objects.remediation_status import RemediationStatus
from app.domain.value_objects.severity import Severity


class PostgresFindingRepository:
    def __init__(self, pool: AsyncConnectionPool[Any]) -> None:
        self._pool = pool

    async def add(self, finding: Finding, evidence_enc: bytes | None) -> None:
        async with self._pool.connection() as conn, conn.transaction():
            await conn.execute(
                "insert into public.findings (id, test_run_id, endpoint_id, title, severity, "
                "priority_score, remediation_status, evidence_enc, detected_at) "
                "values (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    finding.id,
                    finding.test_run_id,
                    finding.endpoint_id,
                    finding.title,
                    finding.severity.value,
                    finding.priority_score,
                    finding.remediation_status.value,
                    evidence_enc,
                    finding.detected_at,
                ),
            )
            for cve_id in finding.cve_ids:
                await conn.execute(
                    "insert into public.finding_cves (finding_id, cve_id) values (%s, %s) "
                    "on conflict do nothing",
                    (finding.id, cve_id),
                )

    async def list_by_scan(self, scan_id: UUID) -> list[Finding]:
        async with self._pool.connection() as conn:
            cursor = await conn.execute(
                "select f.id, f.test_run_id, f.endpoint_id, f.title, f.severity, f.priority_score, "
                "f.remediation_status, f.detected_at, f.is_false_positive, "
                "coalesce((select array_agg(fc.cve_id order by fc.cve_id) "
                "from public.finding_cves fc where fc.finding_id = f.id), '{}') "
                "from public.findings f join public.test_runs r on r.id = f.test_run_id "
                "where r.scan_id = %s order by f.priority_score desc nulls last, f.id",
                (scan_id,),
            )
            rows = await cursor.fetchall()
        return [
            Finding(
                id=row[0],
                test_run_id=row[1],
                endpoint_id=row[2],
                title=row[3],
                severity=Severity(row[4]),
                priority_score=float(row[5]) if row[5] is not None else None,
                remediation_status=RemediationStatus(row[6]),
                detected_at=row[7],
                is_false_positive=row[8],
                cve_ids=tuple(row[9]),
            )
            for row in rows
        ]
