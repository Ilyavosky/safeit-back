import asyncio
from collections.abc import Awaitable, Callable

import structlog

log = structlog.get_logger(__name__)


class AsyncioScanScheduler:
    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[None]] = set()

    def schedule(self, job: Callable[[], Awaitable[None]]) -> None:
        task = asyncio.get_running_loop().create_task(self._run(job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def wait_idle(self) -> None:
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def aclose(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*list(self._tasks), return_exceptions=True)

    @staticmethod
    async def _run(job: Callable[[], Awaitable[None]]) -> None:
        try:
            await job()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("scan_job_crashed")
