from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.container import Container
from app.domain.entities.user import User
from app.domain.value_objects.role import Role
from app.interfaces.api.dependencies import get_container, require_role
from app.interfaces.api.schemas.audit import AuditChainResponse, AuditEntryResponse

router = APIRouter(prefix="/audit", tags=["audit"])

ContainerDep = Annotated[Container, Depends(get_container)]
AdminOnly = Annotated[User, Depends(require_role(Role.ADMIN))]


@router.get("", response_model=list[AuditEntryResponse])
async def list_audit(
    _: AdminOnly,
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    user_id: UUID | None = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
) -> list[AuditEntryResponse]:
    entries = await container.list_audit.execute(
        limit=limit, before_id=before_id, user_id=user_id, action=action
    )
    return [AuditEntryResponse.model_validate(e, from_attributes=True) for e in entries]


@router.get("/verify", response_model=AuditChainResponse)
async def verify_audit_chain(_: AdminOnly, container: ContainerDep) -> AuditChainResponse:
    status = await container.verify_audit_chain.execute()
    return AuditChainResponse(intact=status.intact, broken_at_id=status.broken_at_id)
