from app.application.ports.findings_query import FindingQueryRepository, ReportSummary
from app.domain.entities.user import User
from app.domain.value_objects.role import Role

MAX_REPORTS = 100


class ListReports:
    def __init__(self, findings: FindingQueryRepository) -> None:
        self._findings = findings

    async def execute(self, user: User) -> list[ReportSummary]:
        owner_id = None if user.role is Role.ADMIN else user.id
        return await self._findings.list_reports(owner_id, MAX_REPORTS)
