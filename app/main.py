from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.container import Container, build_container
from app.infrastructure.logging import configure_logging
from app.interfaces.api.error_handlers import register_error_handlers
from app.interfaces.api.middleware.request_id import REQUEST_ID_HEADER, RequestIdMiddleware
from app.interfaces.api.routers import (
    assets,
    audit,
    auth,
    cves,
    dashboard,
    domains,
    findings,
    health,
    reports,
    scans,
    users,
)


def create_app(container: Container | None = None) -> FastAPI:
    resolved = container or build_container(get_settings())
    configure_logging(resolved.settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await resolved.database.open()
        try:
            yield
        finally:
            await resolved.scheduler.aclose()
            await resolved.database.close()

    app = FastAPI(
        title="SafeIT API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if resolved.settings.is_prod else "/docs",
        redoc_url=None,
    )
    app.state.container = resolved

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
        expose_headers=[REQUEST_ID_HEADER],
    )
    app.add_middleware(RequestIdMiddleware)

    register_error_handlers(app)
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(domains.router)
    app.include_router(audit.router)
    app.include_router(cves.router)
    app.include_router(scans.router)
    app.include_router(assets.router)
    app.include_router(findings.router)
    app.include_router(reports.router)
    app.include_router(dashboard.router)
    return app


app = create_app()
