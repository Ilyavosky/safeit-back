from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.entities.asset import Asset
from app.domain.entities.discovered import DiscoveredService, HttpProbe
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.scan import Scan


class ReconScanRepository(Protocol):
    async def add_if_idle(self, scan: Scan) -> bool: ...

    async def fail_stale(self, domain_id: UUID, cutoff: datetime) -> int: ...


class AssetRepository(Protocol):
    async def upsert(self, asset: Asset) -> Asset: ...

    async def replace_services(
        self, asset_id: UUID, services: Sequence[DiscoveredService]
    ) -> None: ...

    async def upsert_endpoint(self, asset_id: UUID, probe: HttpProbe) -> None: ...

    async def list_by_domain(self, domain_id: UUID) -> list[Asset]: ...

    async def get(self, asset_id: UUID) -> Asset | None: ...

    async def list_services(self, asset_id: UUID) -> list[DiscoveredService]: ...

    async def list_endpoints(self, asset_id: UUID) -> list[Endpoint]: ...

    async def get_endpoint(self, endpoint_id: UUID) -> Endpoint | None: ...

    async def set_whitelisted(self, endpoint_id: UUID, whitelisted: bool) -> None: ...
