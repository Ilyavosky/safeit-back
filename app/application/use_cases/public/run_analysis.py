import asyncio
from collections import Counter
from collections.abc import Sequence
from datetime import timedelta
from typing import Any
from uuid import UUID

import structlog

from app.application.ports.clock import Clock
from app.application.ports.llm import (
    LlmGateway,
    PublicHostView,
    PublicSummaryRequest,
)
from app.application.ports.public_analysis import (
    ApexDns,
    CertTransparencySource,
    PublicAnalysisRepository,
    PublicDns,
    PublicWebFetcher,
    WebObservation,
)
from app.application.ports.recon import SubdomainEnumerator
from app.application.ports.testing import ToolExecutionError
from app.domain.entities.public_analysis import PublicAnalysis, PublicHost
from app.domain.errors_llm import LlmUnavailableError
from app.domain.services.public_classifier import (
    classify_host,
    detect_provider,
    security_headers_present,
    technologies_from,
)
from app.domain.services.public_scope import MAX_PUBLIC_HOSTS
from app.domain.services.recon_scope import normalize_host
from app.domain.services.scope_policy import is_host_in_domain
from app.domain.value_objects.job_status import JobStatus

log = structlog.get_logger(__name__)

LLM_HOST_LIMIT = 25

FAILED_MESSAGE = "El análisis no pudo completarse."
CONCURRENCY = 5
TLS_EXPIRY_WARNING = timedelta(days=30)


class RunPublicAnalysis:
    def __init__(
        self,
        analyses: PublicAnalysisRepository,
        dns: PublicDns,
        enumerator: SubdomainEnumerator,
        ct_source: CertTransparencySource,
        fetcher: PublicWebFetcher,
        gateway: LlmGateway | None,
        clock: Clock,
    ) -> None:
        self._analyses = analyses
        self._dns = dns
        self._enumerator = enumerator
        self._ct = ct_source
        self._fetcher = fetcher
        self._gateway = gateway
        self._clock = clock

    async def execute(self, analysis_id: UUID) -> None:
        analysis = await self._analyses.get(analysis_id)
        if analysis is None or analysis.status is not JobStatus.QUEUED:
            return
        await self._analyses.save(analysis.start())
        try:
            await self._run(analysis)
        except Exception as exc:
            log.error("public_analysis_failed", analysis_id=str(analysis_id), exc_info=exc)
            failed = analysis.finish(JobStatus.FAILED, self._clock.now(), error=FAILED_MESSAGE)
            await self._analyses.save(failed)

    async def _run(self, analysis: PublicAnalysis) -> None:
        domain = analysis.domain
        apex = await self._dns.apex(domain)
        hostnames, truncated = await self._discover(domain)
        semaphore = asyncio.Semaphore(CONCURRENCY)

        async def inspect(host: str) -> PublicHost:
            async with semaphore:
                return await self._inspect_host(host, domain, apex)

        hosts = list(await asyncio.gather(*(inspect(h) for h in hostnames)))
        await self._analyses.replace_hosts(analysis.id, hosts)
        stats = self._stats(hosts, apex, truncated)
        summary, model = await self._explain(domain, stats, hosts)
        done = analysis.finish(
            JobStatus.DONE,
            self._clock.now(),
            stats=stats,
            summary=summary,
            summary_model=model,
        )
        await self._analyses.save(done)

    async def _discover(self, domain: str) -> tuple[list[str], bool]:
        passive: list[str] = []
        try:
            passive = await self._enumerator.enumerate(domain)
        except ToolExecutionError as exc:
            log.info("public_passive_enumeration_failed", reason=str(exc))
        certificates = await self._ct.subdomains(domain)
        found: dict[str, None] = {domain: None}
        for raw in (*passive, *certificates):
            host = normalize_host(raw)
            if host is not None and is_host_in_domain(host, domain):
                found[host] = None
        ordered = sorted(found, key=lambda h: (h != domain, h != f"www.{domain}", h))
        return ordered[:MAX_PUBLIC_HOSTS], len(ordered) > MAX_PUBLIC_HOSTS

    async def _inspect_host(self, host: str, domain: str, apex: ApexDns) -> PublicHost:
        observation = await self._fetcher.fetch(host)
        cnames = await self._dns.cnames(host)
        return build_host(host, domain, apex, observation, cnames)

    def _stats(self, hosts: Sequence[PublicHost], apex: ApexDns, truncated: bool) -> dict[str, Any]:
        now = self._clock.now()
        kinds = Counter(h.kind.value for h in hosts)
        with_web = [h for h in hosts if h.http_status is not None]
        return {
            "total_hosts": len(hosts),
            "truncated": truncated,
            "by_kind": dict(kinds),
            "with_web": len(with_web),
            "tls_valid": sum(1 for h in hosts if h.tls_valid is True),
            "tls_invalid": sum(1 for h in hosts if h.tls_valid is False),
            "tls_expiring_soon": sum(
                1
                for h in hosts
                if h.tls_valid_until is not None and h.tls_valid_until - now < TLS_EXPIRY_WARNING
            ),
            "without_hsts": sum(1 for h in with_web if "HSTS" not in h.security_headers),
            "providers": sorted({h.provider for h in hosts if h.provider}),
            "dns": {
                "nameservers": list(apex.nameservers),
                "mail_hosts": list(apex.mail_hosts),
                "spf": apex.has_spf,
                "dmarc": apex.has_dmarc,
                "caa": apex.has_caa,
            },
        }

    async def _explain(
        self, domain: str, stats: dict[str, Any], hosts: Sequence[PublicHost]
    ) -> tuple[str | None, str | None]:
        if self._gateway is None:
            return None, None
        relevant = sorted(hosts, key=lambda h: h.http_status is None)[:LLM_HOST_LIMIT]
        request = PublicSummaryRequest(
            domain=domain,
            stats=stats,
            hosts=tuple(
                PublicHostView(
                    host=h.host,
                    kind=h.kind.value,
                    http_status=h.http_status,
                    title=h.title,
                    technologies=h.technologies,
                    provider=h.provider,
                    security_headers=h.security_headers,
                    tls_valid=h.tls_valid,
                )
                for h in relevant
            ),
        )
        try:
            response = await self._gateway.explain_public(request)
        except LlmUnavailableError as exc:
            log.warning("public_summary_unavailable", domain=domain, reason=str(exc))
            return None, None
        if response.data is None:
            log.warning("public_summary_invalid", domain=domain, error=response.error)
            return None, None
        text = response.data.summary
        if response.data.highlights:
            text += "\n\n" + "\n".join(f"- {item}" for item in response.data.highlights)
        return text, response.model


def build_host(
    host: str,
    domain: str,
    apex: ApexDns,
    observation: WebObservation | None,
    cnames: Sequence[str],
) -> PublicHost:
    if observation is None:
        kind = classify_host(
            host,
            domain,
            http_status=None,
            title=None,
            technologies=(),
            content_type=None,
            redirect_host=None,
            mail_hosts=apex.mail_hosts,
        )
        return PublicHost(host=host, kind=kind, provider=detect_provider({}, cnames))
    technologies = technologies_from(observation.headers, observation.html_head)
    kind = classify_host(
        host,
        domain,
        http_status=observation.http_status,
        title=observation.title,
        technologies=technologies,
        content_type=observation.content_type,
        redirect_host=observation.redirect_host,
        mail_hosts=apex.mail_hosts,
    )
    tls = observation.tls
    return PublicHost(
        host=host,
        kind=kind,
        http_status=observation.http_status,
        title=observation.title,
        technologies=technologies,
        provider=detect_provider(observation.headers, cnames),
        redirect_host=observation.redirect_host,
        security_headers=security_headers_present(observation.headers),
        tls_issuer=tls.issuer if tls else None,
        tls_valid=tls.valid if tls else None,
        tls_valid_until=tls.valid_until if tls else None,
    )
