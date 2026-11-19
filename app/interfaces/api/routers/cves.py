from typing import Annotated

from fastapi import APIRouter, Depends

from app.container import Container
from app.interfaces.api.dependencies import CurrentUser, get_container
from app.interfaces.api.schemas.cves import CveResponse

router = APIRouter(prefix="/cves", tags=["cves"])

ContainerDep = Annotated[Container, Depends(get_container)]


@router.get("/{cve_id}", response_model=CveResponse)
async def read_cve(cve_id: str, _: CurrentUser, container: ContainerDep) -> CveResponse:
    return CveResponse.from_record(await container.lookup_cve.execute(cve_id))
