from dataclasses import dataclass
from uuid import UUID

from app.application.ports.recon_repositories import AssetRepository
from app.application.ports.repositories import DomainRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.asset import Asset
from app.domain.entities.discovered import DiscoveredService
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError, OutOfScopeError


@dataclass(frozen=True)
class AssetDetail:
    asset: Asset
    services: list[DiscoveredService]
    endpoints: list[Endpoint]


class ListAssets:
    def __init__(self, domains: DomainRepository, assets: AssetRepository) -> None:
        self._domains = domains
        self._assets = assets

    async def execute(self, user: User, domain_id: UUID) -> list[Asset]:
        domain = await load_domain(self._domains, user, domain_id, owner_only=False)
        return await self._assets.list_by_domain(domain.id)


class GetAsset:
    def __init__(self, domains: DomainRepository, assets: AssetRepository) -> None:
        self._domains = domains
        self._assets = assets

    async def execute(self, user: User, asset_id: UUID) -> AssetDetail:
        asset = await self._assets.get(asset_id)
        if asset is None:
            raise EntityNotFoundError("asset", asset_id)
        await load_domain(self._domains, user, asset.domain_id, owner_only=False)
        return AssetDetail(
            asset,
            await self._assets.list_services(asset.id),
            await self._assets.list_endpoints(asset.id),
        )


class SetEndpointWhitelist:
    def __init__(
        self, domains: DomainRepository, assets: AssetRepository, audit: RecordAction
    ) -> None:
        self._domains = domains
        self._assets = assets
        self._audit = audit

    async def execute(self, user: User, endpoint_id: UUID, whitelisted: bool) -> Endpoint:
        endpoint = await self._assets.get_endpoint(endpoint_id)
        if endpoint is None:
            raise EntityNotFoundError("endpoint", endpoint_id)
        await load_domain(self._domains, user, endpoint.domain_id, owner_only=False)
        if whitelisted and not endpoint.in_scope:
            raise OutOfScopeError
        await self._assets.set_whitelisted(endpoint.id, whitelisted)
        await self._audit.execute(
            "endpoint.whitelist_changed",
            user_id=user.id,
            entity="endpoint",
            entity_id=endpoint.id,
            detail={"url": endpoint.url[:255], "whitelisted": whitelisted},
        )
        return Endpoint(
            endpoint.id,
            endpoint.asset_id,
            endpoint.domain_id,
            endpoint.url,
            endpoint.http_status,
            endpoint.technologies,
            whitelisted,
            endpoint.in_scope,
        )
