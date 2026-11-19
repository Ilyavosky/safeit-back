import asyncio
from uuid import UUID

import structlog

from app.application.ports.testing_repositories import ScanRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.llm.analyze_findings import AnalyzeFindings
from app.application.use_cases.llm.generate_report import GenerateReport
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.scan_type import ScanType

log = structlog.get_logger(__name__)


class FinalizeScan:
    def __init__(
        self,
        scans: ScanRepository,
        analyze: AnalyzeFindings,
        report: GenerateReport,
        audit: RecordAction,
        timeout_seconds: int,
    ) -> None:
        self._scans = scans
        self._analyze = analyze
        self._report = report
        self._audit = audit
        self._timeout = timeout_seconds

    async def execute(self, scan_id: UUID) -> None:
        scan = await self._scans.get(scan_id)
        if scan is None or scan.type is not ScanType.TESTS or scan.status is not JobStatus.DONE:
            return
        for step, action in (("analysis", self._analyze.execute), ("report", self._report.execute)):
            try:
                async with asyncio.timeout(self._timeout):
                    await action(scan)
            except TimeoutError:
                await self._failed(scan.started_by, scan_id, step, "timeout")
            except Exception:
                log.exception("finalize_step_failed", step=step, scan_id=str(scan_id))
                await self._failed(scan.started_by, scan_id, step, "error")

    async def _failed(self, user_id: UUID, scan_id: UUID, step: str, reason: str) -> None:
        await self._audit.execute(
            "scan.finalize_failed",
            user_id=user_id,
            entity="scan",
            entity_id=scan_id,
            detail={"step": step, "reason": reason},
        )
