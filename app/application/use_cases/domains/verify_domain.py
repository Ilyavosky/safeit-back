from uuid import UUID

from app.application.ports.clock import Clock
from app.application.ports.domain_verifier import DomainVerifier
from app.application.ports.repositories import DomainRepository
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter
from app.application.use_cases.domains.access import load_domain
from app.domain.entities.domain import Domain
from app.domain.entities.user import User
from app.domain.errors import DomainAlreadyClaimedError, DomainVerificationFailedError

_NOT_FOUND = (
    "No se encontró el registro o archivo de verificación. "
    "Revisa las instrucciones y vuelve a intentarlo."
)


class VerifyDomain:
    def __init__(
        self,
        domains: DomainRepository,
        verifier: DomainVerifier,
        audit: RecordAction,
        limiter: AuthRateLimiter,
        clock: Clock,
    ) -> None:
        self._domains = domains
        self._verifier = verifier
        self._audit = audit
        self._limiter = limiter
        self._clock = clock

    async def execute(self, user: User, domain_id: UUID) -> Domain:
        await self._limiter.check(f"domain-verify:user:{user.id}")
        domain = await load_domain(self._domains, user, domain_id, owner_only=True)
        if domain.is_verified:
            return domain
        method = domain.verification_method
        confirmed = await self._verifier.is_verified(domain.name, method, domain.verification_token)
        if not confirmed:
            await self._record(user, domain, "domain.verification_failed")
            raise DomainVerificationFailedError(_NOT_FOUND)
        verified = domain.mark_verified(self._clock.now())
        try:
            await self._domains.save(verified)
        except DomainAlreadyClaimedError:
            await self._record(user, domain, "domain.claim_rejected")
            raise
        await self._record(user, verified, "domain.verified")
        return verified

    async def _record(self, user: User, domain: Domain, action: str) -> None:
        await self._audit.execute(
            action,
            user_id=user.id,
            entity="domain",
            entity_id=domain.id,
            detail={"name": domain.name, "method": domain.verification_method.value},
        )
