from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.application.use_cases.recon.assets import AssetDetail
from app.domain.entities.asset import Asset
from app.domain.entities.discovered import DiscoveredService
from app.domain.entities.endpoint import Endpoint
from app.domain.value_objects.asset_kind import AssetKind


class AssetResponse(BaseModel):
    id: UUID
    domain_id: UUID
    kind: AssetKind
    value: str
    in_scope: bool
    discovered_at: datetime

    @classmethod
    def from_asset(cls, asset: Asset) -> "AssetResponse":
        return cls(
            id=asset.id,
            domain_id=asset.domain_id,
            kind=asset.kind,
            value=asset.value,
            in_scope=asset.in_scope,
            discovered_at=asset.discovered_at,
        )


class ServiceResponse(BaseModel):
    port: int
    protocol: str
    name: str | None
    version: str | None
    banner: str | None

    @classmethod
    def from_service(cls, service: DiscoveredService) -> "ServiceResponse":
        return cls(
            port=service.port,
            protocol=service.protocol,
            name=service.name,
            version=service.version,
            banner=service.banner,
        )


class EndpointResponse(BaseModel):
    id: UUID
    url: str
    http_status: int | None
    technologies: list[str]
    whitelisted: bool

    @classmethod
    def from_endpoint(cls, endpoint: Endpoint) -> "EndpointResponse":
        return cls(
            id=endpoint.id,
            url=endpoint.url,
            http_status=endpoint.http_status,
            technologies=list(endpoint.technologies),
            whitelisted=endpoint.whitelisted,
        )


class AssetDetailResponse(AssetResponse):
    services: list[ServiceResponse]
    endpoints: list[EndpointResponse]

    @classmethod
    def from_detail(cls, detail: AssetDetail) -> "AssetDetailResponse":
        base = AssetResponse.from_asset(detail.asset)
        return cls(
            **base.model_dump(),
            services=[ServiceResponse.from_service(s) for s in detail.services],
            endpoints=[EndpointResponse.from_endpoint(e) for e in detail.endpoints],
        )


class WhitelistRequest(BaseModel):
    whitelisted: bool
