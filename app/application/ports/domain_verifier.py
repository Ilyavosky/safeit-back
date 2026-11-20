from typing import Protocol

from app.domain.value_objects.verification_method import VerificationMethod


class DomainVerifier(Protocol):
    async def is_verified(self, name: str, method: VerificationMethod, token: str) -> bool: ...
