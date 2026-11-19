import dns.asyncresolver
import dns.exception
import dns.resolver
import structlog

from app.domain.services.domain_verification import dns_record_name

log = structlog.get_logger(__name__)


class DnsTxtVerifier:
    def __init__(
        self, resolver: dns.asyncresolver.Resolver | None = None, lifetime: float = 5.0
    ) -> None:
        self._resolver = resolver or dns.asyncresolver.Resolver()
        self._lifetime = lifetime

    async def check(self, name: str, token: str) -> bool:
        record = dns_record_name(name)
        try:
            answer = await self._resolver.resolve(record, "TXT", lifetime=self._lifetime)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.name.NameTooLong,
            dns.name.LabelTooLong,
        ) as exc:
            log.info("dns_verification_miss", record=record, reason=type(exc).__name__)
            return False
        return any(_joined(rdata) == token for rdata in answer)


def _joined(rdata: object) -> str:
    strings = getattr(rdata, "strings", ())
    return b"".join(strings).decode("utf-8", errors="ignore").strip()
