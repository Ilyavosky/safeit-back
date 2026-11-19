from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.domain import errors
from app.domain.errors_queue import QueueUnavailableError

log = structlog.get_logger(__name__)

_STATUS_BY_ERROR: tuple[tuple[type[errors.DomainError], int], ...] = (
    (errors.EntityNotFoundError, 404),
    (errors.ConflictError, 409),
    (errors.InvalidCredentialsError, 401),
    (errors.MfaRequiredError, 401),
    (errors.InvalidMfaCodeError, 401),
    (errors.InvalidTokenError, 401),
    (errors.TokenReuseDetectedError, 401),
    (errors.PermissionDeniedError, 403),
    (errors.InvalidCveIdError, 422),
    (errors.InvalidCursorError, 422),
    (errors.FeedUnavailableError, 503),
    (QueueUnavailableError, 503),
    (errors.InvalidDomainNameError, 422),
    (errors.DomainNotVerifiedError, 422),
    (errors.DomainVerificationFailedError, 422),
    (errors.OutOfScopeError, 403),
    (errors.ToolNotAllowedError, 403),
    (errors.LlmOutputRejectedError, 422),
    (errors.WeakPasswordError, 422),
    (errors.RateLimitExceededError, 429),
)

_SECURITY_STATUSES = frozenset({401, 403, 429})

_HTTP_CODES = {404: "not_found", 405: "method_not_allowed"}
_HTTP_MESSAGES = {
    404: "No se encontró el recurso solicitado.",
    405: "Método no permitido.",
}


def status_for(exc: errors.DomainError) -> int:
    for error_type, status in _STATUS_BY_ERROR:
        if isinstance(exc, error_type):
            return status
    return 400


def _response(
    request: Request,
    status: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": getattr(request.state, "request_id", None),
    }
    if details is not None:
        body["details"] = details
    return JSONResponse(status_code=status, content=body)


async def _domain_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, errors.DomainError)
    status = status_for(exc)
    if status in _SECURITY_STATUSES:
        log.warning("security_event", code=exc.code, status=status, path=request.url.path)
    return _response(request, status, exc.code, exc.message)


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    details = [
        {"loc": list(item["loc"]), "message": item["msg"], "type": item["type"]}
        for item in exc.errors()
    ]
    return _response(
        request, 422, "validation_error", "Los datos enviados no son válidos.", details
    )


async def _http_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = _HTTP_CODES.get(exc.status_code, "http_error")
    message = _HTTP_MESSAGES.get(exc.status_code, str(exc.detail))
    response = _response(request, exc.status_code, code, message)
    if exc.headers:
        response.headers.update(exc.headers)
    return response


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    log.error(
        "unhandled_error",
        error=type(exc).__name__,
        path=request.url.path,
        exc_info=exc,
    )
    return _response(request, 500, "internal_error", "Ocurrió un error inesperado.")


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(errors.DomainError, _domain_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
