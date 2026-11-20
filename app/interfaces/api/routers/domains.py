from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.container import Container
from app.domain.entities.user import User
from app.domain.value_objects.role import Role
from app.interfaces.api.dependencies import CurrentUser, get_container, require_role
from app.interfaces.api.schemas.domains import DomainCreateRequest, DomainResponse

router = APIRouter(prefix="/domains", tags=["domains"])

ContainerDep = Annotated[Container, Depends(get_container)]
Operator = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=DomainResponse)
async def create_domain(
    body: DomainCreateRequest, user: Operator, container: ContainerDep
) -> DomainResponse:
    domain = await container.add_domain.execute(user, body.name, body.verification_method)
    return DomainResponse.from_domain(domain)


@router.get("", response_model=list[DomainResponse])
async def list_domains(user: CurrentUser, container: ContainerDep) -> list[DomainResponse]:
    domains = await container.list_domains.execute(user)
    return [DomainResponse.from_domain(domain) for domain in domains]


@router.get("/{domain_id}", response_model=DomainResponse)
async def read_domain(
    domain_id: UUID, user: CurrentUser, container: ContainerDep
) -> DomainResponse:
    return DomainResponse.from_domain(await container.get_domain.execute(user, domain_id))


@router.post("/{domain_id}/verify", response_model=DomainResponse)
async def verify_domain(domain_id: UUID, user: Operator, container: ContainerDep) -> DomainResponse:
    return DomainResponse.from_domain(await container.verify_domain.execute(user, domain_id))
