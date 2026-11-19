import asyncio
from uuid import UUID

from celery import Celery
from kombu.exceptions import KombuError

from app.domain.errors_queue import QueueUnavailableError
from app.infrastructure.queue.celery_app import RECON_TASK_NAME


class CeleryReconQueue:
    def __init__(self, app: Celery) -> None:
        self._app = app

    async def enqueue(self, scan_id: UUID, only_host: str | None) -> None:
        try:
            await asyncio.to_thread(
                self._app.send_task, RECON_TASK_NAME, args=[str(scan_id), only_host]
            )
        except (KombuError, OSError) as exc:
            raise QueueUnavailableError from exc
