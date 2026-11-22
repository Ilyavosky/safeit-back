import ipaddress
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.container import Container
from app.domain.entities.user import User
from app.domain.errors import InvalidTokenError, PermissionDeniedError
from app.domain.value_objects.role import Role

_bearer = HTTPBearer(auto_error=False, description="Access token de la sesión")


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


def get_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    hops = get_container(request).settings.trusted_proxy_hops
    if hops == 0:
        return peer
    forwarded = [
        part.strip()
        for part in request.headers.get("x-forwarded-for", "").split(",")
        if part.strip()
    ]
    if len(forwarded) < hops:
        return peer
    try:
        return str(ipaddress.ip_address(forwarded[-hops]))
    except ValueError:
        return peer


async def get_current_user(
    container: Annotated[Container, Depends(get_container)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if credentials is None:
        raise InvalidTokenError
    return await container.authenticate.execute(credentials.credentials)


CurrentUser = Annotated[User, Depends(get_current_user)]
ClientIp = Annotated[str, Depends(get_client_ip)]


def require_role(*allowed: Role) -> Callable[[User], Awaitable[User]]:
    async def checker(user: CurrentUser) -> User:
        if user.role not in allowed:
            raise PermissionDeniedError
        return user

    return checker
