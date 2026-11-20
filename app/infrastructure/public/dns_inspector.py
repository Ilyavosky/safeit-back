import dns.asyncresolver
import dns.exception
import dns.resolver

from app.application.ports.public_analysis import ApexDns
from app.domain.services.recon_scope import normalize_host

_DNS_ERRORS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
    dns.name.NameTooLong,
    dns.name.LabelTooLong,
)


def _txt(rdata: object) -> str:
    strings = getattr(rdata, "strings", ())
    return b"".join(strings).decode("utf-8", errors="ignore")


class DnsPublicInspector:
    def __init__(
        self, resolver: dns.asyncresolver.Resolver | None = None, lifetime: float = 5.0
    ) -> None:
        self._resolver = resolver or dns.asyncresolver.Resolver()
        self._lifetime = lifetime

    async def _query(self, name: str, rtype: str) -> list[object]:
        try:
            answer = await self._resolver.resolve(name, rtype, lifetime=self._lifetime)
        except _DNS_ERRORS:
            return []
        return list(answer)

    async def apex(self, domain: str) -> ApexDns:
        ns = await self._query(domain, "NS")
        mx = await self._query(domain, "MX")
        txt = [_txt(r) for r in await self._query(domain, "TXT")]
        dmarc = [_txt(r) for r in await self._query(f"_dmarc.{domain}", "TXT")]
        caa = await self._query(domain, "CAA")
        return ApexDns(
            nameservers=_hosts(getattr(r, "target", None) for r in ns),
            mail_hosts=_hosts(getattr(r, "exchange", None) for r in mx),
            has_spf=any(t.lower().startswith("v=spf1") for t in txt),
            has_dmarc=any(t.lower().startswith("v=dmarc1") for t in dmarc),
            has_caa=bool(caa),
        )

    async def cnames(self, host: str) -> list[str]:
        records = await self._query(host, "CNAME")
        return list(_hosts(getattr(r, "target", None) for r in records))


def _hosts(targets: object) -> tuple[str, ...]:
    found: dict[str, None] = {}
    for target in targets:  # type: ignore[attr-defined]
        if target is None:
            continue
        host = normalize_host(str(target))
        if host is not None:
            found[host] = None
    return tuple(found)
