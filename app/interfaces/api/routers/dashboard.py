from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from app.container import Container
from app.interfaces.api.dependencies import CurrentUser, get_container
from app.interfaces.api.schemas.reports import DashboardResponse

router = APIRouter(tags=["dashboard"])

ContainerDep = Annotated[Container, Depends(get_container)]


@router.get("/dashboard/summary", response_model=DashboardResponse)
async def dashboard_summary(
    user: CurrentUser,
    container: ContainerDep,
    domain_id: UUID | None = None,
    scan_id: UUID | None = None,
) -> DashboardResponse:
    summary = await container.dashboard.execute(user, domain_id=domain_id, scan_id=scan_id)
    return DashboardResponse.from_summary(summary)
