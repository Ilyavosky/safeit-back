from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response

from app.container import Container
from app.domain.entities.user import User
from app.domain.value_objects.role import Role
from app.interfaces.api.dependencies import CurrentUser, get_container, require_role
from app.interfaces.api.schemas.reports import (
    LatestReportResponse,
    RecommendationResponse,
    RecommendationStatusRequest,
    ReportResponse,
    ReportSummaryResponse,
)

router = APIRouter(tags=["reports"])

ContainerDep = Annotated[Container, Depends(get_container)]
Operator = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]


@router.get("/reports", response_model=list[ReportSummaryResponse])
async def list_reports(user: CurrentUser, container: ContainerDep) -> list[ReportSummaryResponse]:
    summaries = await container.list_reports.execute(user)
    return [ReportSummaryResponse.from_summary(s) for s in summaries]


@router.get("/reports/latest", response_model=LatestReportResponse)
async def read_latest_report(user: CurrentUser, container: ContainerDep) -> LatestReportResponse:
    return LatestReportResponse(scan_id=await container.latest_report_scan.execute(user))


@router.get("/reports/{scan_id}", response_model=ReportResponse)
async def read_report(scan_id: UUID, user: CurrentUser, container: ContainerDep) -> ReportResponse:
    return ReportResponse.from_document(await container.get_report.execute(user, scan_id))


@router.get(
    "/reports/{scan_id}/pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}},
)
async def download_report_pdf(
    scan_id: UUID, user: CurrentUser, container: ContainerDep
) -> Response:
    pdf = await container.render_report_pdf.execute(user, scan_id)
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="reporte-{scan_id}.pdf"'},
    )


@router.patch("/recommendations/{recommendation_id}", response_model=RecommendationResponse)
async def update_recommendation(
    recommendation_id: UUID,
    body: RecommendationStatusRequest,
    user: Operator,
    container: ContainerDep,
) -> RecommendationResponse:
    rec = await container.update_recommendation.execute(user, recommendation_id, body.status)
    return RecommendationResponse.from_recommendation(rec)
