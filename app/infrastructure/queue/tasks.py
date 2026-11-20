import asyncio
from uuid import UUID

import structlog

from app.config import get_settings
from app.container import Container, build_container
from app.infrastructure.queue.celery_app import (
    CVE_SYNC_TASK_NAME,
    PUBLIC_ANALYSIS_TASK_NAME,
    PUBLIC_PURGE_TASK_NAME,
    RECON_TASK_NAME,
    create_celery,
)

celery_app = create_celery(get_settings())
log = structlog.get_logger("app.cve_sync")


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


async def run_cve_sync_job(container: Container) -> bool:
    result = await container.sync_cve_catalog.execute()
    log.info(
        "cve_sync_finished",
        targets=result.targets,
        changed=result.changed,
        lookups_skipped=result.lookups_skipped,
        complete=result.complete,
    )
    return result.complete


async def _sync_main() -> bool:
    container = build_container(get_settings())
    await container.database.open()
    try:
        return await run_cve_sync_job(container)
    finally:
        await container.database.close()


@celery_app.task(  # type: ignore[untyped-decorator]
    name=CVE_SYNC_TASK_NAME, soft_time_limit=3000, time_limit=3300
)
def sync_cve() -> bool:
    return asyncio.run(_sync_main())


async def _public_main(analysis_id: UUID) -> None:
    container = build_container(get_settings())
    await container.database.open()
    try:
        await container.run_public_analysis.execute(analysis_id)
    finally:
        await container.database.close()


@celery_app.task(name=PUBLIC_ANALYSIS_TASK_NAME)  # type: ignore[untyped-decorator]
def run_public_analysis(analysis_id: str) -> None:
    asyncio.run(_public_main(UUID(analysis_id)))


async def _purge_main() -> int:
    container = build_container(get_settings())
    await container.database.open()
    try:
        return await container.purge_public_analyses.execute()
    finally:
        await container.database.close()


@celery_app.task(name=PUBLIC_PURGE_TASK_NAME)  # type: ignore[untyped-decorator]
def purge_public_analyses() -> int:
    return asyncio.run(_purge_main())
