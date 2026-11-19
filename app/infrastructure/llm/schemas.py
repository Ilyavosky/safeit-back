from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.entities.llm_proposals import (
    CorrelationItem,
    CorrelationProposal,
    FalsePositiveProposal,
    FalsePositiveVerdict,
    PlanProposal,
    ProposedTest,
    RecommendationDraft,
    ReportDraft,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PlanTestOut(_Strict):
    endpoint_id: UUID
    tool: str = Field(min_length=1, max_length=50)
    params: dict[str, Any] = Field(default_factory=dict)


class PlanOut(_Strict):
    tests: list[PlanTestOut] = Field(max_length=200)
    justification: str = Field(min_length=1, max_length=1000)

    def to_domain(self) -> PlanProposal:
        return PlanProposal(
            tuple(ProposedTest(t.endpoint_id, t.tool, t.params) for t in self.tests),
            self.justification,
        )


class CorrelationItemOut(_Strict):
    finding_id: UUID
    cve_ids: list[str] = Field(max_length=20)
    note: str = Field(default="", max_length=1000)


class CorrelationOut(_Strict):
    items: list[CorrelationItemOut] = Field(max_length=200)

    def to_domain(self) -> CorrelationProposal:
        return CorrelationProposal(
            tuple(CorrelationItem(i.finding_id, tuple(i.cve_ids), i.note) for i in self.items)
        )


class VerdictOut(_Strict):
    finding_id: UUID
    is_false_positive: bool
    justification: str = Field(default="", max_length=1000)


class FalsePositiveOut(_Strict):
    verdicts: list[VerdictOut] = Field(max_length=200)

    def to_domain(self) -> FalsePositiveProposal:
        return FalsePositiveProposal(
            tuple(
                FalsePositiveVerdict(v.finding_id, v.is_false_positive, v.justification)
                for v in self.verdicts
            )
        )


class RecommendationOut(_Strict):
    finding_id: UUID
    priority: int = Field(ge=1, le=1000)
    action: str = Field(min_length=1, max_length=1000)


class ReportOut(_Strict):
    summary: str = Field(min_length=1, max_length=4000)
    recommendations: list[RecommendationOut] = Field(max_length=100)

    def to_domain(self) -> ReportDraft:
        return ReportDraft(
            self.summary,
            tuple(
                RecommendationDraft(r.finding_id, r.priority, r.action)
                for r in self.recommendations
            ),
        )
