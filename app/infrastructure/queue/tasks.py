import asyncio
from uuid import UUID

from app.config import get_settings
from app.container import Container, build_container
from app.infrastructure.queue.celery_app import RECON_TASK_NAME, create_celery

celery_app = create_celery(get_settings())


async def run_recon_job(container: Container, scan_id: UUID, only_host: str | None) -> None:
    await container.run_recon_scan.execute(scan_id, only_host)


async def _main(scan_id: UUID, only_host: str | None) -> None:
    container = build_container(get_settings())
    await container.database.open()
    try:
        await run_recon_job(container, scan_id, only_host)
    finally:
        await container.database.close()


@celery_app.task(name=RECON_TASK_NAME)  # type: ignore[untyped-decorator]
def run_recon(scan_id: str, only_host: str | None = None) -> None:
    asyncio.run(_main(UUID(scan_id), only_host))
