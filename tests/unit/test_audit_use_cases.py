from uuid import uuid4

from app.application.use_cases.audit.list_audit import MAX_PAGE_SIZE, ListAudit
from app.application.use_cases.audit.record_action import RecordAction
from app.application.use_cases.audit.verify_chain import VerifyAuditChain
from tests.fakes import InMemoryAuditRepository


async def test_record_action_persists_entry() -> None:
    repo = InMemoryAuditRepository()
    user_id, entity_id = uuid4(), uuid4()
    await RecordAction(repo).execute(
        "domain.created", user_id=user_id, entity="domain", entity_id=entity_id, detail={"a": 1}
    )
    entry = repo.entries[0]
    assert (entry.action, entry.user_id, entry.entity_id, entry.detail) == (
        "domain.created",
        user_id,
        entity_id,
        {"a": 1},
    )


async def test_list_audit_filters_and_orders_newest_first() -> None:
    repo = InMemoryAuditRepository()
    record = RecordAction(repo)
    user_id = uuid4()
    await record.execute("a", user_id=user_id)
    await record.execute("b")
    await record.execute("a")
    listing = ListAudit(repo)
    assert [e.id for e in await listing.execute()] == [3, 2, 1]
    assert [e.id for e in await listing.execute(action="a")] == [3, 1]
    assert [e.id for e in await listing.execute(user_id=user_id)] == [1]
    assert [e.id for e in await listing.execute(before_id=3)] == [2, 1]


async def test_list_audit_clamps_page_size() -> None:
    repo = InMemoryAuditRepository()
    record = RecordAction(repo)
    for _ in range(MAX_PAGE_SIZE + 5):
        await record.execute("x")
    listing = ListAudit(repo)
    assert len(await listing.execute(limit=10_000)) == MAX_PAGE_SIZE
    assert len(await listing.execute(limit=0)) == 1


async def test_verify_chain_reports_status() -> None:
    repo = InMemoryAuditRepository()
    verify = VerifyAuditChain(repo)
    assert (await verify.execute()).intact is True
    repo.broken_at = 7
    status = await verify.execute()
    assert (status.intact, status.broken_at_id) == (False, 7)
