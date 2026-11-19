from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.container import Container
from app.domain.entities.user import User
from app.domain.value_objects.role import Role
from app.interfaces.api.dependencies import CurrentUser, get_container, require_role
from app.interfaces.api.schemas.scans import (
    FindingResponse,
    ScanResponse,
    TestRunResponse,
)

router = APIRouter(tags=["scans"])

ContainerDep = Annotated[Container, Depends(get_container)]
Operator = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]


@router.post(
    "/domains/{domain_id}/tests",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
)
async def start_tests(domain_id: UUID, user: Operator, container: ContainerDep) -> ScanResponse:
    return ScanResponse.from_scan(await container.start_tests.execute(user, domain_id))


@router.post(
    "/domains/{domain_id}/scans",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
)
async def start_recon(domain_id: UUID, user: Operator, container: ContainerDep) -> ScanResponse:
    return ScanResponse.from_scan(await container.start_recon_scan.execute(user, domain_id))


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def read_scan(scan_id: UUID, user: CurrentUser, container: ContainerDep) -> ScanResponse:
    return ScanResponse.from_scan(await container.get_scan.execute(user, scan_id))


@router.get("/scans/{scan_id}/test-runs", response_model=list[TestRunResponse])
async def read_test_runs(
    scan_id: UUID, user: CurrentUser, container: ContainerDep
) -> list[TestRunResponse]:
    runs = await container.list_test_runs.execute(user, scan_id)
    return [TestRunResponse.from_run(run) for run in runs]


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def read_findings(
    scan_id: UUID, user: CurrentUser, container: ContainerDep
) -> list[FindingResponse]:
    findings = await container.list_scan_findings.execute(user, scan_id)
    return [FindingResponse.from_finding(finding) for finding in findings]
