from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from app.domain.entities.discovered import DiscoveredService, HttpProbe


class SubdomainEnumerator(Protocol):
    async def enumerate(self, domain: str) -> list[str]: ...


class HostResolver(Protocol):
    async def resolve(self, host: str) -> list[str]: ...


class PortScanner(Protocol):
    async def scan(self, addresses: Sequence[str]) -> dict[str, list[DiscoveredService]]: ...


class HttpProber(Protocol):
    async def probe(self, hosts: Sequence[str]) -> list[HttpProbe]: ...


class ReconQueue(Protocol):
    async def enqueue(self, scan_id: UUID, only_host: str | None) -> None: ...
