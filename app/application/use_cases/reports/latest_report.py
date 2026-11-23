from uuid import UUID

from app.application.ports.findings_query import FindingQueryRepository
from app.domain.entities.user import User
from app.domain.value_objects.role import Role


class GetLatestReportScan:
    def __init__(self, findings: FindingQueryRepository) -> None:
        self._findings = findings

    async def execute(self, user: User) -> UUID | None:
        owner_id = None if user.role is Role.ADMIN else user.id
        return await self._findings.latest_report_scan_id(owner_id)
