import asyncio

from app.infrastructure.verification.well_known_file import Resolve, system_resolve


class SystemHostResolver:
    def __init__(self, resolve: Resolve = system_resolve, timeout: float = 10.0) -> None:
        self._resolve = resolve
        self._timeout = timeout

    async def resolve(self, host: str) -> list[str]:
        try:
            async with asyncio.timeout(self._timeout):
                addresses = await self._resolve(host, 443)
        except (TimeoutError, OSError):
            return []
        return sorted(set(addresses))
