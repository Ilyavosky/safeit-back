import asyncio

from argon2 import (
    DEFAULT_MEMORY_COST,
    DEFAULT_PARALLELISM,
    DEFAULT_TIME_COST,
    PasswordHasher,
)
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Argon2PasswordHasher:
    def __init__(
        self,
        time_cost: int | None = None,
        memory_cost: int | None = None,
        parallelism: int | None = None,
    ) -> None:
        self._hasher = PasswordHasher(
            time_cost=time_cost if time_cost is not None else DEFAULT_TIME_COST,
            memory_cost=memory_cost if memory_cost is not None else DEFAULT_MEMORY_COST,
            parallelism=parallelism if parallelism is not None else DEFAULT_PARALLELISM,
        )
        self._dummy_hash = self._hasher.hash("safeit-dummy-password")

    async def hash(self, password: str) -> str:
        return await asyncio.to_thread(self._hasher.hash, password)

    async def verify(self, password_hash: str, password: str) -> bool:
        return await asyncio.to_thread(self._verify, password_hash, password)

    async def verify_dummy(self, password: str) -> None:
        await asyncio.to_thread(self._verify, self._dummy_hash, password)

    def _verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
