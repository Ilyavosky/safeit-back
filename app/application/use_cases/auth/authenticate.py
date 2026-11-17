from app.application.ports.repositories import UserRepository
from app.application.ports.token_service import TokenService
from app.domain.entities.user import User
from app.domain.errors import InvalidTokenError


class AuthenticateAccessToken:
    def __init__(self, users: UserRepository, tokens: TokenService) -> None:
        self._users = users
        self._tokens = tokens

    async def execute(self, access_token: str) -> User:
        claims = self._tokens.decode_access_token(access_token)
        user = await self._users.get_by_id(claims.user_id)
        if user is None:
            raise InvalidTokenError
        return user
