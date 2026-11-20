from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from app.domain.entities.report import Recommendation, Report
from app.domain.value_objects.recommendation_status import RecommendationStatus
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True)
class RecommendationRef:
    recommendation: Recommendation
    scan_id: UUID


class ReportRepository(Protocol):
    async def get_by_scan(self, scan_id: UUID) -> Report | None: ...

    async def add(self, report: Report, recommendations: Sequence[Recommendation]) -> None: ...

    async def list_recommendations(self, report_id: UUID) -> list[Recommendation]: ...

    async def get_recommendation(self, recommendation_id: UUID) -> RecommendationRef | None: ...

    async def set_recommendation_status(
        self, recommendation_id: UUID, status: RecommendationStatus
    ) -> None: ...


@dataclass(frozen=True)
class RecommendationLine:
    id: UUID
    finding_id: UUID
    finding_title: str
    severity: Severity
    url: str
    priority: int
    action: str
    status: RecommendationStatus


@dataclass(frozen=True)
class ReportDocument:
    scan_id: UUID
    domain: str
    created_at: datetime
    summary: str
    counts: dict[Severity, int]
    recommendations: list[RecommendationLine]
    generated_with_llm: bool

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class ReportRenderer(Protocol):
    def render(self, document: ReportDocument) -> bytes: ...
