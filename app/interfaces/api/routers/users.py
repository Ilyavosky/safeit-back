from typing import Annotated

from fastapi import APIRouter, Depends

from app.container import Container
from app.interfaces.api.dependencies import CurrentUser, get_container
from app.interfaces.api.schemas.auth import ProfileUpdateRequest, UserResponse

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def read_me(user: CurrentUser) -> UserResponse:
    return UserResponse.model_validate(user, from_attributes=True)


@router.patch("/me", response_model=UserResponse)
async def update_me(
    body: ProfileUpdateRequest,
    user: CurrentUser,
    container: Annotated[Container, Depends(get_container)],
) -> UserResponse:
    updated = await container.update_profile.execute(
        user,
        current_password=body.current_password,
        email=body.email,
        new_password=body.new_password,
    )
    return UserResponse.model_validate(updated, from_attributes=True)
