import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from psycopg_pool import AsyncConnectionPool

from app.domain.entities.domain import Domain
from app.domain.entities.user import User
from app.domain.errors import ConflictError, DomainAlreadyClaimedError
from app.domain.services.domain_verification import new_verification_token
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.role import Role
from app.domain.value_objects.verification_method import VerificationMethod
from app.infrastructure.db.audit_repository import PostgresAuditRepository
from app.infrastructure.db.domain_repository import PostgresDomainRepository
from app.infrastructure.db.user_repository import PostgresUserRepository


async def _user(pool: AsyncConnectionPool[Any], email: str) -> User:
    user = User(
        id=uuid4(),
        email=email,
        password_hash="hash",
        role=Role.ANALYST,
        totp_secret_enc=None,
        mfa_enabled=False,
        created_at=datetime.now(UTC),
    )
    await PostgresUserRepository(pool).add(user)
    return user


def _domain(user_id: UUID, name: str = "example.com") -> Domain:
    return Domain(
        id=uuid4(),
        user_id=user_id,
        name=name,
        verification_method=VerificationMethod.DNS_TXT,
        verification_token=new_verification_token(),
        status=DomainStatus.PENDING,
        verified_at=None,
    )


async def test_domain_repository_roundtrip(migrated_pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresDomainRepository(migrated_pool)
    ana = await _user(migrated_pool, "ana@example.com")
    luis = await _user(migrated_pool, "luis@example.com")
    first, second = _domain(ana.id, "b.example.com"), _domain(ana.id, "a.example.com")
    await repo.add(first)
    await repo.add(second)
    await repo.add(_domain(luis.id, "b.example.com"))

    assert await repo.get_by_id(first.id) == first
    assert await repo.get_by_user_and_name(ana.id, "a.example.com") == second
    assert await repo.get_by_user_and_name(luis.id, "a.example.com") is None
    assert [d.name for d in await repo.list_by_user(ana.id)] == ["a.example.com", "b.example.com"]
    assert len(await repo.list_all()) == 3
    assert await repo.get_by_id(uuid4()) is None
    with pytest.raises(ConflictError):
        await repo.add(_domain(ana.id, "a.example.com"))


async def test_only_one_user_can_verify_a_domain(migrated_pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresDomainRepository(migrated_pool)
    ana = await _user(migrated_pool, "ana@example.com")
    luis = await _user(migrated_pool, "luis@example.com")
    mine, theirs = _domain(ana.id), _domain(luis.id)
    await repo.add(mine)
    await repo.add(theirs)
    assert await repo.get_verified_by_name("example.com") is None

    verified = mine.mark_verified(datetime.now(UTC))
    await repo.save(verified)
    stored = await repo.get_by_id(mine.id)
    assert stored is not None
    assert stored.is_verified
    assert stored.verified_at is not None
    found = await repo.get_verified_by_name("example.com")
    assert found is not None
    assert found.id == mine.id

    with pytest.raises(DomainAlreadyClaimedError):
        await repo.save(theirs.mark_verified(datetime.now(UTC)))
    pending = await repo.get_by_id(theirs.id)
    assert pending is not None
    assert not pending.is_verified


async def test_audit_repository_records_and_lists(migrated_pool: AsyncConnectionPool[Any]) -> None:
    repo = PostgresAuditRepository(migrated_pool)
    user = await _user(migrated_pool, "ana@example.com")
    entity_id = uuid4()
    await repo.record(
        user_id=user.id,
        action="domain.created",
        entity="domain",
        entity_id=entity_id,
        detail={"name": "example.com", "id": entity_id},
    )
    await repo.record(
        user_id=None, action="auth.login_failed", entity=None, entity_id=None, detail={}
    )
    await repo.record(
        user_id=user.id, action="domain.verified", entity=None, entity_id=None, detail={}
    )

    entries = await repo.list_entries(limit=10, before_id=None, user_id=None, action=None)
    assert [e.action for e in entries] == ["domain.verified", "auth.login_failed", "domain.created"]
    oldest = entries[-1]
    assert oldest.detail == {"name": "example.com", "id": str(entity_id)}
    assert oldest.prev_hash is None
    assert entries[1].prev_hash == oldest.hash
    assert entries[0].prev_hash == entries[1].hash

    by_user = await repo.list_entries(limit=10, before_id=None, user_id=user.id, action=None)
    assert [e.action for e in by_user] == ["domain.verified", "domain.created"]
    by_action = await repo.list_entries(
        limit=10, before_id=None, user_id=None, action="auth.login_failed"
    )
    assert len(by_action) == 1
    page = await repo.list_entries(limit=1, before_id=entries[0].id, user_id=None, action=None)
    assert [e.id for e in page] == [entries[1].id]
    assert await repo.first_broken_id() is None


async def test_concurrent_writes_keep_the_chain_intact(
    migrated_pool: AsyncConnectionPool[Any],
) -> None:
    repo = PostgresAuditRepository(migrated_pool)
    await asyncio.gather(
        *(
            repo.record(
                user_id=None, action=f"load.{i}", entity=None, entity_id=None, detail={"i": i}
            )
            for i in range(25)
        )
    )
    entries = await repo.list_entries(limit=200, before_id=None, user_id=None, action=None)
    assert len(entries) == 25
    assert len({e.hash for e in entries}) == 25
    assert await repo.first_broken_id() is None
