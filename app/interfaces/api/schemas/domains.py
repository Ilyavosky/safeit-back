from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, StringConstraints

from app.domain.entities.domain import Domain
from app.domain.services.domain_verification import dns_record_name, file_path
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.verification_method import VerificationMethod

DomainName = Annotated[str, StringConstraints(min_length=1, max_length=253)]


class DomainCreateRequest(BaseModel):
    name: DomainName
    verification_method: VerificationMethod


class VerificationInstructions(BaseModel):
    method: VerificationMethod
    location: str
    value: str


class DomainResponse(BaseModel):
    id: UUID
    name: str
    status: DomainStatus
    verified_at: datetime | None
    verification: VerificationInstructions

    @classmethod
    def from_domain(cls, domain: Domain) -> "DomainResponse":
        if domain.verification_method is VerificationMethod.DNS_TXT:
            location = dns_record_name(domain.name)
        else:
            location = file_path(domain.verification_token)
        return cls(
            id=domain.id,
            name=domain.name,
            status=domain.status,
            verified_at=domain.verified_at,
            verification=VerificationInstructions(
                method=domain.verification_method,
                location=location,
                value=domain.verification_token,
            ),
        )
