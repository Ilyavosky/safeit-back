from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.verification_method import VerificationMethod


@dataclass(frozen=True)
class Domain:
    id: UUID
    user_id: UUID
    name: str
    verification_method: VerificationMethod
    verification_token: str
    status: DomainStatus
    verified_at: datetime | None

    @property
    def is_verified(self) -> bool:
        return self.status is DomainStatus.VERIFIED

    def mark_verified(self, at: datetime) -> "Domain":
        return replace(self, status=DomainStatus.VERIFIED, verified_at=at)
