from dataclasses import dataclass
from uuid import UUID

from app.application.ports.clock import Clock
from app.application.ports.public_analysis import PublicAnalysisRepository
from app.domain.entities.public_analysis import PublicAnalysis, PublicHost
from app.domain.entities.user import User
from app.domain.errors import EntityNotFoundError
from app.domain.value_objects.role import Role

LIST_LIMIT = 20


@dataclass(frozen=True)
class PublicAnalysisDetail:
    analysis: PublicAnalysis
    hosts: list[PublicHost]


class GetPublicAnalysis:
    def __init__(self, analyses: PublicAnalysisRepository, clock: Clock) -> None:
        self._analyses = analyses
        self._clock = clock

    async def execute(self, user: User, analysis_id: UUID) -> PublicAnalysisDetail:
        analysis = await self._analyses.get(analysis_id)
        if (
            analysis is None
            or analysis.expires_at <= self._clock.now()
            or (analysis.user_id != user.id and user.role is not Role.ADMIN)
        ):
            raise EntityNotFoundError("public_analysis", analysis_id)
        return PublicAnalysisDetail(analysis, await self._analyses.list_hosts(analysis.id))


class ListPublicAnalyses:
    def __init__(self, analyses: PublicAnalysisRepository) -> None:
        self._analyses = analyses

    async def execute(self, user: User) -> list[PublicAnalysis]:
        return await self._analyses.list_by_user(user.id, LIST_LIMIT)


class PurgeExpiredPublicAnalyses:
    def __init__(self, analyses: PublicAnalysisRepository, clock: Clock) -> None:
        self._analyses = analyses
        self._clock = clock

    async def execute(self) -> int:
        return await self._analyses.delete_expired(self._clock.now())
