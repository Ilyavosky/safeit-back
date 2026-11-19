from uuid import uuid4

import pytest

from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.auth.session import AuthRateLimiter
from app.application.use_cases.domains.add_domain import AddDomain
from app.application.use_cases.domains.get_domain import GetDomain
from app.application.use_cases.domains.list_domains import ListDomains
from app.application.use_cases.domains.verify_domain import VerifyDomain
from app.domain.entities.user import User
from app.domain.errors import (
    ConflictError,
    DomainAlreadyClaimedError,
    DomainVerificationFailedError,
    EntityNotFoundError,
    InvalidDomainNameError,
    RateLimitExceededError,
)
from app.domain.value_objects.domain_status import DomainStatus
from app.domain.value_objects.role import Role
from app.domain.value_objects.verification_method import VerificationMethod
from app.infrastructure.rate_limit import InMemoryRateLimiter
from tests.fakes import (
    FakeClock,
    FakeDomainVerifier,
    InMemoryAuditRepository,
    InMemoryDomainRepository,
)


def _user(role: Role = Role.ANALYST) -> User:
    return User(
        id=uuid4(),
        email=f"{uuid4().hex[:8]}@example.com",
        password_hash="x",
        role=role,
        totp_secret_enc=None,
        mfa_enabled=False,
        created_at=FakeClock().now(),
    )


class Env:
    def __init__(self, verify_attempts: int = 100) -> None:
        self.clock = FakeClock()
        self.domains = InMemoryDomainRepository()
        self.audit = InMemoryAuditRepository()
        self.verifier = FakeDomainVerifier()
        record = RecordAction(self.audit)
        self.add = AddDomain(self.domains, record)
        self.get = GetDomain(self.domains)
        self.list = ListDomains(self.domains)
        self.verify = VerifyDomain(
            self.domains,
            self.verifier,
            record,
            AuthRateLimiter(InMemoryRateLimiter(self.clock), verify_attempts, 60),
            self.clock,
        )


async def test_add_domain_normalizes_and_audits() -> None:
    env, owner = Env(), _user()
    domain = await env.add.execute(owner, "  Example.COM. ", VerificationMethod.DNS_TXT)
    assert domain.name == "example.com"
    assert domain.status is DomainStatus.PENDING
    assert domain.verified_at is None
    assert domain.verification_token.startswith("safeit-verification=")
    assert env.audit.actions() == ["domain.created"]


async def test_add_domain_rejects_invalid_name_and_duplicates() -> None:
    env, owner = Env(), _user()
    with pytest.raises(InvalidDomainNameError):
        await env.add.execute(owner, "localhost", VerificationMethod.FILE)
    await env.add.execute(owner, "example.com", VerificationMethod.FILE)
    with pytest.raises(ConflictError):
        await env.add.execute(owner, "EXAMPLE.com", VerificationMethod.DNS_TXT)


async def test_two_users_can_add_the_same_pending_domain() -> None:
    env = Env()
    await env.add.execute(_user(), "example.com", VerificationMethod.FILE)
    await env.add.execute(_user(), "example.com", VerificationMethod.FILE)


async def test_verify_domain_success_marks_verified() -> None:
    env, owner = Env(), _user()
    domain = await env.add.execute(owner, "example.com", VerificationMethod.DNS_TXT)
    env.verifier.verified_names.add("example.com")
    verified = await env.verify.execute(owner, domain.id)
    assert verified.is_verified
    assert verified.verified_at == env.clock.now()
    assert env.verifier.calls == [
        ("example.com", VerificationMethod.DNS_TXT, domain.verification_token)
    ]
    assert env.audit.actions() == ["domain.created", "domain.verified"]
    assert (await env.get.execute(owner, domain.id)).is_verified


async def test_verify_domain_failure_keeps_pending_and_audits() -> None:
    env, owner = Env(), _user()
    domain = await env.add.execute(owner, "example.com", VerificationMethod.FILE)
    with pytest.raises(DomainVerificationFailedError):
        await env.verify.execute(owner, domain.id)
    assert not (await env.get.execute(owner, domain.id)).is_verified
    assert env.audit.actions() == ["domain.created", "domain.verification_failed"]


async def test_verify_is_idempotent_for_verified_domains() -> None:
    env, owner = Env(), _user()
    domain = await env.add.execute(owner, "example.com", VerificationMethod.FILE)
    env.verifier.verified_names.add("example.com")
    await env.verify.execute(owner, domain.id)
    env.verifier.verified_names.clear()
    assert (await env.verify.execute(owner, domain.id)).is_verified
    assert len(env.verifier.calls) == 1


async def test_second_user_cannot_claim_verified_domain() -> None:
    env, first, second = Env(), _user(), _user()
    pending = await env.add.execute(second, "example.com", VerificationMethod.FILE)
    domain = await env.add.execute(first, "example.com", VerificationMethod.FILE)
    env.verifier.verified_names.add("example.com")
    await env.verify.execute(first, domain.id)
    with pytest.raises(DomainAlreadyClaimedError):
        await env.add.execute(_user(), "example.com", VerificationMethod.DNS_TXT)
    with pytest.raises(DomainAlreadyClaimedError):
        await env.verify.execute(second, pending.id)
    assert "domain.claim_rejected" in env.audit.actions()
    assert not (await env.get.execute(second, pending.id)).is_verified


async def test_only_owner_can_verify_and_others_get_not_found() -> None:
    env, owner, stranger, admin = Env(), _user(), _user(), _user(Role.ADMIN)
    domain = await env.add.execute(owner, "example.com", VerificationMethod.FILE)
    env.verifier.verified_names.add("example.com")
    for actor in (stranger, admin):
        with pytest.raises(EntityNotFoundError):
            await env.verify.execute(actor, domain.id)
    with pytest.raises(EntityNotFoundError):
        await env.get.execute(stranger, domain.id)
    assert (await env.get.execute(admin, domain.id)).id == domain.id
    assert env.verifier.calls == []


async def test_list_domains_scopes_by_role() -> None:
    env, ana, luis, admin = Env(), _user(), _user(), _user(Role.ADMIN)
    await env.add.execute(ana, "b.example.com", VerificationMethod.FILE)
    await env.add.execute(ana, "a.example.com", VerificationMethod.FILE)
    await env.add.execute(luis, "c.example.com", VerificationMethod.FILE)
    assert [d.name for d in await env.list.execute(ana)] == ["a.example.com", "b.example.com"]
    assert [d.name for d in await env.list.execute(luis)] == ["c.example.com"]
    assert len(await env.list.execute(admin)) == 3


async def test_verify_is_rate_limited_per_user() -> None:
    env, owner = Env(verify_attempts=2), _user()
    domain = await env.add.execute(owner, "example.com", VerificationMethod.FILE)
    for _ in range(2):
        with pytest.raises(DomainVerificationFailedError):
            await env.verify.execute(owner, domain.id)
    with pytest.raises(RateLimitExceededError):
        await env.verify.execute(owner, domain.id)
    assert len(env.verifier.calls) == 2
