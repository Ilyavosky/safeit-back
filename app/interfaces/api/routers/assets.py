from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.container import Container
from app.domain.entities.user import User
from app.domain.value_objects.role import Role
from app.interfaces.api.dependencies import CurrentUser, get_container, require_role
from app.interfaces.api.schemas.assets import (
    AssetDetailResponse,
    AssetResponse,
    EndpointResponse,
    WhitelistRequest,
)
from app.interfaces.api.schemas.scans import ScanResponse

router = APIRouter(tags=["assets"])

ContainerDep = Annotated[Container, Depends(get_container)]
Operator = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]


@router.get("/assets", response_model=list[AssetResponse])
async def list_assets(
    domain: Annotated[UUID, Query()], user: CurrentUser, container: ContainerDep
) -> list[AssetResponse]:
    assets = await container.list_assets.execute(user, domain)
    return [AssetResponse.from_asset(asset) for asset in assets]


@router.get("/assets/{asset_id}", response_model=AssetDetailResponse)
async def read_asset(
    asset_id: UUID, user: CurrentUser, container: ContainerDep
) -> AssetDetailResponse:
    return AssetDetailResponse.from_detail(await container.get_asset.execute(user, asset_id))


@router.post(
    "/assets/{asset_id}/rescan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
)
async def rescan_asset(asset_id: UUID, user: Operator, container: ContainerDep) -> ScanResponse:
    return ScanResponse.from_scan(await container.rescan_asset.execute(user, asset_id))


@router.put("/endpoints/{endpoint_id}/whitelist", response_model=EndpointResponse)
async def set_whitelist(
    endpoint_id: UUID, body: WhitelistRequest, user: Operator, container: ContainerDep
) -> EndpointResponse:
    endpoint = await container.set_endpoint_whitelist.execute(user, endpoint_id, body.whitelisted)
    return EndpointResponse.from_endpoint(endpoint)
