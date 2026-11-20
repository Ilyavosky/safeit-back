from collections.abc import Sequence
from uuid import UUID

import structlog

from app.application.llm_budget import TokenBudget
from app.application.ports.cve_catalog import CveRepository
from app.application.ports.llm import (
    CveView,
    FindingForReview,
    FindingReviewRepository,
    LlmGateway,
    ReviewItem,
    ReviewRequest,
)
from app.application.ports.repositories import DomainRepository
from app.application.ports.secret_cipher import DecryptionError, SecretCipher
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.llm.recorder import DecisionRecorder
from app.domain.entities.cve import CveRecord
from app.domain.entities.scan import Scan
from app.domain.errors import DomainError, InvalidCveIdError
from app.domain.services.cve_id import normalize_cve_id
from app.domain.services.finding_priority import finding_priority
from app.domain.services.risk_scoring import priority_score
from app.domain.value_objects.llm_kind import LlmKind

log = structlog.get_logger(__name__)

MAX_EVIDENCE_CHARS = 1500
MAX_REVIEWED_FINDINGS = 200
MAX_JUSTIFICATION = 1000


class AnalyzeFindings:
    def __init__(
        self,
        *,
        domains: DomainRepository,
        review: FindingReviewRepository,
        cves: CveRepository,
        gateway: LlmGateway | None,
        recorder: DecisionRecorder,
        budget: TokenBudget,
        cipher: SecretCipher,
        audit: RecordAction,
    ) -> None:
        self._domains = domains
        self._review = review
        self._cves = cves
        self._gateway = gateway
        self._recorder = recorder
        self._budget = budget
        self._cipher = cipher
        self._audit = audit

    async def execute(self, scan: Scan) -> None:
        if self._gateway is None:
            return
        domain = await self._domains.get_by_id(scan.domain_id)
        if domain is None:
            return
        stats = {"correlated": 0, "cves_attached": 0, "false_positives": 0, "rejected": 0}
        items = (await self._review.list_for_review(scan.id))[:MAX_REVIEWED_FINDINGS]
        if items and self._budget.has_room(scan.id):
            await self._correlate(self._gateway, scan, domain.name, items, stats)
            items = (await self._review.list_for_review(scan.id))[:MAX_REVIEWED_FINDINGS]
        if items and self._budget.has_room(scan.id):
            await self._false_positives(self._gateway, scan, domain.name, items, stats)
        await self._audit.execute(
            "scan.analysis_finished",
            user_id=scan.started_by,
            entity="scan",
            entity_id=scan.id,
            detail={**stats, "tokens": self._budget.used(scan.id)},
        )

    async def _request(self, domain: str, items: Sequence[ReviewItem]) -> ReviewRequest:
        catalog = await self._cves.get_many(sorted({c for i in items for c in i.finding.cve_ids}))
        return ReviewRequest(
            domain=domain,
            findings=tuple(
                FindingForReview(
                    id=item.finding.id,
                    title=item.finding.title,
                    severity=item.finding.severity,
                    tool=item.tool_name,
                    url=item.url,
                    evidence=self._evidence(item),
                    cves=tuple(_cve_view(catalog[c]) for c in item.finding.cve_ids if c in catalog),
                )
                for item in items
            ),
        )

    def _evidence(self, item: ReviewItem) -> str:
        if not item.evidence_enc:
            return ""
        try:
            text = self._cipher.decrypt(
                item.evidence_enc.decode("ascii"), f"scan-result:{item.finding.id}"
            )
        except (DecryptionError, UnicodeDecodeError):
            return ""
        return text[:MAX_EVIDENCE_CHARS]

    async def _correlate(
        self,
        gateway: LlmGateway,
        scan: Scan,
        domain: str,
        items: Sequence[ReviewItem],
        stats: dict[str, int],
    ) -> None:
        request = await self._request(domain, items)
        try:
            response = await gateway.correlate(request)
        except DomainError as exc:
            log.warning("llm_correlation_unavailable", reason=exc.code)
            return
        if response.data is None:
            await self._recorder.record(
                scan.id,
                LlmKind.CORRELATION,
                request,
                response,
                validated=False,
                justification=response.error,
            )
            return
        by_id = {i.finding.id: i for i in items}
        proposed: dict[UUID, set[str]] = {}
        for entry in response.data.items:
            if entry.finding_id not in by_id:
                stats["rejected"] += 1
                continue
            normalized = _normalize_all(entry.cve_ids)
            proposed.setdefault(entry.finding_id, set()).update(normalized)
        catalog = await self._cves.get_many(sorted({c for ids in proposed.values() for c in ids}))
        discarded = sum(1 for ids in proposed.values() for c in ids if c not in catalog)
        await self._recorder.record(
            scan.id,
            LlmKind.CORRELATION,
            request,
            response,
            validated=True,
            justification=f"CVE descartados por no estar en el catálogo: {discarded}",
        )
        for finding_id, ids in proposed.items():
            item = by_id[finding_id]
            new = sorted(c for c in ids if c in catalog and c not in item.finding.cve_ids)
            if not new:
                continue
            merged = [*item.finding.cve_ids, *new]
            records = await self._cves.get_many(merged)
            score = finding_priority(
                item.finding.severity,
                [p for r in records.values() if (p := _priority(r)) is not None],
            )
            await self._review.attach_cves(finding_id, merged, score)
            stats["correlated"] += 1
            stats["cves_attached"] += len(new)

    async def _false_positives(
        self,
        gateway: LlmGateway,
        scan: Scan,
        domain: str,
        items: Sequence[ReviewItem],
        stats: dict[str, int],
    ) -> None:
        request = await self._request(domain, items)
        try:
            response = await gateway.review_false_positives(request)
        except DomainError as exc:
            log.warning("llm_false_positive_unavailable", reason=exc.code)
            return
        if response.data is None:
            await self._recorder.record(
                scan.id,
                LlmKind.FALSE_POSITIVE,
                request,
                response,
                validated=False,
                justification=response.error,
            )
            return
        valid: dict[UUID, str] = {}
        rejected = 0
        known = {i.finding.id for i in items}
        for verdict in response.data.verdicts:
            reason = verdict.justification.strip()
            if verdict.finding_id not in known or not verdict.is_false_positive:
                continue
            if not reason:
                rejected += 1
                continue
            valid[verdict.finding_id] = reason[:MAX_JUSTIFICATION]
        decision = await self._recorder.record(
            scan.id,
            LlmKind.FALSE_POSITIVE,
            request,
            response,
            validated=True,
            justification=f"Veredictos sin justificación descartados: {rejected}",
        )
        for finding_id, reason in valid.items():
            await self._review.mark_false_positive(finding_id, reason, decision.id)
        stats["false_positives"] += len(valid)
        stats["rejected"] += rejected


def _priority(record: CveRecord) -> float | None:
    return priority_score(record.cvss_score, record.epss_score, record.in_cisa_kev)


def _cve_view(record: CveRecord) -> CveView:
    return CveView(
        record.cve_id, record.cvss_score, record.epss_score, record.in_cisa_kev, _priority(record)
    )


def _normalize_all(raw: Sequence[str]) -> set[str]:
    found: set[str] = set()
    for value in raw:
        try:
            found.add(normalize_cve_id(value))
        except InvalidCveIdError:
            continue
    return found
