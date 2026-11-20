from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from app.container import Container
from app.interfaces.api.dependencies import CurrentUser, get_container
from app.interfaces.api.schemas.public_analyses import (
    PublicAnalysisCreate,
    PublicAnalysisDetailResponse,
    PublicAnalysisResponse,
)

router = APIRouter(prefix="/public-analyses", tags=["public-analyses"])

ContainerDep = Annotated[Container, Depends(get_container)]


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=PublicAnalysisResponse,
)
async def start_public_analysis(
    payload: PublicAnalysisCreate, user: CurrentUser, container: ContainerDep
) -> PublicAnalysisResponse:
    analysis = await container.start_public_analysis.execute(
        user, payload.domain, payload.accept_notice
    )
    return PublicAnalysisResponse.from_analysis(analysis)


@router.get("", response_model=list[PublicAnalysisResponse])
async def list_public_analyses(
    user: CurrentUser, container: ContainerDep
) -> list[PublicAnalysisResponse]:
    analyses = await container.list_public_analyses.execute(user)
    return [PublicAnalysisResponse.from_analysis(item) for item in analyses]


@router.get("/{analysis_id}", response_model=PublicAnalysisDetailResponse)
async def read_public_analysis(
    analysis_id: UUID, user: CurrentUser, container: ContainerDep
) -> PublicAnalysisDetailResponse:
    detail = await container.get_public_analysis.execute(user, analysis_id)
    return PublicAnalysisDetailResponse.from_detail(detail)
