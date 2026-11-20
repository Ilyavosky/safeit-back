from uuid import uuid4

from app.application.ports.repositories import DomainRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.domain.entities.domain import Domain
from app.domain.entities.user import User
from app.domain.errors import ConflictError, DomainAlreadyClaimedError
from app.domain.services.domain_name import normalize_domain_name
from app.domain.services.domain_verification import new_verification_token
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.verification_method import VerificationMethod


class AddDomain:
    def __init__(self, domains: DomainRepository, audit: RecordAction) -> None:
        self._domains = domains
        self._audit = audit

    async def execute(self, user: User, raw_name: str, method: VerificationMethod) -> Domain:
        name = normalize_domain_name(raw_name)
        if await self._domains.get_by_user_and_name(user.id, name) is not None:
            raise ConflictError("Ya registraste este dominio.")
        claimed = await self._domains.get_verified_by_name(name)
        if claimed is not None and claimed.user_id != user.id:
            raise DomainAlreadyClaimedError
        domain = Domain(
            id=uuid4(),
            user_id=user.id,
            name=name,
            verification_method=method,
            verification_token=new_verification_token(),
            status=DomainStatus.PENDING,
            verified_at=None,
        )
        await self._domains.add(domain)
        await self._audit.execute(
            "domain.created",
            user_id=user.id,
            entity="domain",
            entity_id=domain.id,
            detail={"name": name, "method": method.value},
        )
        return domain
