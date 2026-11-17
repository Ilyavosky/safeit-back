from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.container import Container
from app.interfaces.api.dependencies import get_container

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(
    container: Annotated[Container, Depends(get_container)],
) -> JSONResponse:
    database_up = await container.database.ping()
    if database_up:
        return JSONResponse({"status": "ok", "database": "up"})
    return JSONResponse({"status": "degraded", "database": "down"}, status_code=503)
