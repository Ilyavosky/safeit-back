import asyncio
import sys

from app.config import get_settings
from app.container import build_container


async def sync() -> int:
    container = build_container(get_settings())
    await container.database.open()
    try:
        result = await container.sync_cve_catalog.execute()
    finally:
        await container.database.close()
    print(
        f"CVE objetivo: {result.targets}, cambios: {result.changed}, "
        f"consultas omitidas: {result.lookups_skipped}"
    )
    if not result.complete:
        print(
            f"Sincronización incompleta (kev={result.kev_ok}, nvd={result.nvd_ok}, "
            f"epss={result.epss_ok}). Se conservó el catálogo existente.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(sync()))
