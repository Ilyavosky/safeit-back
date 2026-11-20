from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.finding import Finding
from app.domain.entities.llm_decision import LlmDecision
from app.domain.entities.llm_proposals import (
    CorrelationProposal,
    FalsePositiveProposal,
    PlanProposal,
    PublicSummaryDraft,
    ReportDraft,
)
from app.domain.entities.planned_test import PlannedTest
from app.domain.entities.scan import Scan
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class LlmResponse[T]:
    model: str
    tokens: int
    raw: Any
    data: T | None
    error: str | None = None


@dataclass(frozen=True)
class EndpointView:
    id: UUID
    url: str
    http_status: int | None
    technologies: tuple[str, ...]


@dataclass(frozen=True)
class ToolView:
    name: str
    allowed_params: Mapping[str, Any]


@dataclass(frozen=True)
class PlanRequest:
    domain: str
    endpoints: tuple[EndpointView, ...]
    tools: tuple[ToolView, ...]


@dataclass(frozen=True)
class CveView:
    cve_id: str
    cvss_score: float | None
    epss_score: float | None
    in_cisa_kev: bool
    priority_score: float | None


@dataclass(frozen=True)
class FindingForReview:
    id: UUID
    title: str
    severity: Severity
    tool: str
    url: str
    evidence: str
    cves: tuple[CveView, ...]


@dataclass(frozen=True)
class ReviewRequest:
    domain: str
    findings: tuple[FindingForReview, ...]


@dataclass(frozen=True)
class ReportFindingView:
    id: UUID
    title: str
    severity: Severity
    priority_score: float | None
    url: str


@dataclass(frozen=True)
class ReportRequest:
    domain: str
    counts: Mapping[str, int]
    findings: tuple[ReportFindingView, ...]


@dataclass(frozen=True)
class PublicHostView:
    host: str
    kind: str
    http_status: int | None
    title: str | None
    technologies: tuple[str, ...]
    provider: str | None
    security_headers: tuple[str, ...]
    tls_valid: bool | None


@dataclass(frozen=True)
class PublicSummaryRequest:
    domain: str
    stats: Mapping[str, Any]
    hosts: tuple[PublicHostView, ...]


class LlmGateway(Protocol):
    @property
    def model(self) -> str: ...

    async def plan(self, request: PlanRequest) -> LlmResponse[PlanProposal]: ...

    async def correlate(self, request: ReviewRequest) -> LlmResponse[CorrelationProposal]: ...

    async def review_false_positives(
        self, request: ReviewRequest
    ) -> LlmResponse[FalsePositiveProposal]: ...

    async def report(self, request: ReportRequest) -> LlmResponse[ReportDraft]: ...

    async def explain_public(
        self, request: PublicSummaryRequest
    ) -> LlmResponse[PublicSummaryDraft]: ...


class LlmDecisionRepository(Protocol):
    async def add(self, decision: LlmDecision) -> None: ...

    async def list_by_scan(self, scan_id: UUID) -> list[LlmDecision]: ...


@dataclass(frozen=True)
class ReviewItem:
    finding: Finding
    tool_name: str
    url: str
    evidence_enc: bytes | None


class FindingReviewRepository(Protocol):
    async def list_for_review(self, scan_id: UUID) -> list[ReviewItem]: ...

    async def attach_cves(
        self, finding_id: UUID, cve_ids: Sequence[str], priority: float | None
    ) -> None: ...

    async def mark_false_positive(
        self, finding_id: UUID, justification: str, decision_id: UUID
    ) -> None: ...


@dataclass(frozen=True)
class PlanResult:
    tests: list[PlannedTest]
    decision_id: UUID | None = None


class PlanSource(Protocol):
    async def plan(
        self,
        scan: Scan,
        domain_name: str,
        endpoints: Sequence[Endpoint],
        tools: Mapping[str, AllowedTool],
    ) -> PlanResult: ...


class ScanFinalizer(Protocol):
    async def execute(self, scan_id: UUID) -> None: ...
