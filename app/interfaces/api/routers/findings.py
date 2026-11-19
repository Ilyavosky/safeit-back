from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.application.ports.findings_query import FindingFilter, FindingSort
from app.container import Container
from app.domain.entities.user import User
from app.domain.value_objects.finding_lifecycle import FindingLifecycle
from app.domain.value_objects.role import Role
from app.domain.value_objects.severity import Severity
from app.interfaces.api.dependencies import CurrentUser, get_container, require_role
from app.interfaces.api.schemas.findings import (
    FindingDetailResponse,
    FindingPageResponse,
    FindingStatusRequest,
)

router = APIRouter(tags=["findings"])

ContainerDep = Annotated[Container, Depends(get_container)]
Operator = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]


@router.get("/findings", response_model=FindingPageResponse)
async def list_findings(
    user: CurrentUser,
    container: ContainerDep,
    severity: Severity | None = None,
    status: FindingLifecycle | None = None,
    asset_id: UUID | None = None,
    domain_id: UUID | None = None,
    scan_id: UUID | None = None,
    sort: FindingSort = FindingSort.PRIORITY,
    cursor: str | None = Query(default=None, max_length=300),
    limit: int = Query(default=25, ge=1, le=100),
) -> FindingPageResponse:
    filters = FindingFilter(severity, status, asset_id, domain_id, scan_id)
    page = await container.list_findings.execute(user, filters, sort, cursor, limit)
    return FindingPageResponse.from_page(page)


@router.get("/findings/{finding_id}", response_model=FindingDetailResponse)
async def read_finding(
    finding_id: UUID, user: CurrentUser, container: ContainerDep
) -> FindingDetailResponse:
    return FindingDetailResponse.from_view(await container.get_finding.execute(user, finding_id))


@router.patch("/findings/{finding_id}/status", response_model=FindingDetailResponse)
async def update_finding_status(
    finding_id: UUID, body: FindingStatusRequest, user: Operator, container: ContainerDep
) -> FindingDetailResponse:
    view = await container.update_finding_status.execute(user, finding_id, body.status, body.reason)
    return FindingDetailResponse.from_view(view)
