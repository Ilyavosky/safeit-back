from typing import Protocol
from uuid import UUID

from app.domain.entities.allowed_tool import AllowedTool
from app.domain.entities.endpoint import Endpoint
from app.domain.entities.finding import Finding
from app.domain.entities.scan import Scan
from app.domain.entities.test_run import TestRun


class ScanRepository(Protocol):
    async def add(self, scan: Scan) -> None: ...

    async def get(self, scan_id: UUID) -> Scan | None: ...

    async def save(self, scan: Scan) -> None: ...


class EndpointRepository(Protocol):
    async def list_testable(self, domain_id: UUID) -> list[Endpoint]: ...


class ToolRepository(Protocol):
    async def get_by_name(self, name: str) -> AllowedTool | None: ...

    async def list_active(self) -> list[AllowedTool]: ...


class TestRunRepository(Protocol):
    async def add(self, run: TestRun) -> None: ...

    async def save(self, run: TestRun, result_enc: bytes | None) -> None: ...

    async def list_by_scan(self, scan_id: UUID) -> list[TestRun]: ...


class FindingRepository(Protocol):
    async def add(self, finding: Finding, evidence_enc: bytes | None) -> None: ...

    async def list_by_scan(self, scan_id: UUID) -> list[Finding]: ...
