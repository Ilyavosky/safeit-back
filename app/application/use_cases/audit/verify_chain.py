from dataclasses import dataclass

import structlog

from app.application.ports.repositories import AuditRepository

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class AuditChainStatus:
    intact: bool
    broken_at_id: int | None


class VerifyAuditChain:
    def __init__(self, audit: AuditRepository) -> None:
        self._audit = audit

    async def execute(self) -> AuditChainStatus:
        broken_at = await self._audit.first_broken_id()
        if broken_at is not None:
            log.error("audit_chain_broken", broken_at_id=broken_at)
        return AuditChainStatus(intact=broken_at is None, broken_at_id=broken_at)
