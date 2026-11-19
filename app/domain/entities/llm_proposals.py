from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class ProposedTest:
    endpoint_id: UUID
    tool: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlanProposal:
    tests: tuple[ProposedTest, ...]
    justification: str


@dataclass(frozen=True)
class CorrelationItem:
    finding_id: UUID
    cve_ids: tuple[str, ...]
    note: str


@dataclass(frozen=True)
class CorrelationProposal:
    items: tuple[CorrelationItem, ...]


@dataclass(frozen=True)
class FalsePositiveVerdict:
    finding_id: UUID
    is_false_positive: bool
    justification: str


@dataclass(frozen=True)
class FalsePositiveProposal:
    verdicts: tuple[FalsePositiveVerdict, ...]


@dataclass(frozen=True)
class RecommendationDraft:
    finding_id: UUID
    priority: int
    action: str


@dataclass(frozen=True)
class ReportDraft:
    summary: str
    recommendations: tuple[RecommendationDraft, ...]
