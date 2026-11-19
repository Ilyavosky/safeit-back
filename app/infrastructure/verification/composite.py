from typing import Protocol

from app.domain.value_objects.verification_method import VerificationMethod


class _Check(Protocol):
    async def check(self, name: str, token: str) -> bool: ...


class CompositeDomainVerifier:
    def __init__(self, dns_txt: _Check, file: _Check) -> None:
        self._checks: dict[VerificationMethod, _Check] = {
            VerificationMethod.DNS_TXT: dns_txt,
            VerificationMethod.FILE: file,
        }

    async def is_verified(self, name: str, method: VerificationMethod, token: str) -> bool:
        return await self._checks[method].check(name, token)
