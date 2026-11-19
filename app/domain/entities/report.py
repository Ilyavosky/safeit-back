from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.recommendation_status import RecommendationStatus


@dataclass(frozen=True)
class Report:
    id: UUID
    scan_id: UUID
    decision_id: UUID | None
    summary: str
    content: str
    created_at: datetime


@dataclass(frozen=True)
class Recommendation:
    id: UUID
    report_id: UUID
    finding_id: UUID
    priority: int
    action: str
    status: RecommendationStatus
