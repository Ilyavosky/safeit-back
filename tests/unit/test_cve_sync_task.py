from types import SimpleNamespace
from typing import Any

from app.infrastructure.queue.tasks import run_cve_sync_job


class FakeSync:
    def __init__(self, complete: bool) -> None:
        self.complete = complete

    async def execute(self) -> SimpleNamespace:
        return SimpleNamespace(targets=3, changed=2, lookups_skipped=0, complete=self.complete)


async def test_job_reports_completion() -> None:
    container: Any = SimpleNamespace(sync_cve_catalog=FakeSync(True))

    assert await run_cve_sync_job(container) is True


async def test_job_reports_incomplete_feeds() -> None:
    container: Any = SimpleNamespace(sync_cve_catalog=FakeSync(False))

    assert await run_cve_sync_job(container) is False
