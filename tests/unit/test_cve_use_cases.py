import pytest

from app.application.ports.cve_catalog import NvdCve
from app.application.use_cases.cve.lookup_cve import LookupCve
from app.application.use_cases.cve.sync_catalog import SyncCveCatalog
from app.domain.errors import EntityNotFoundError, FeedUnavailableError, InvalidCveIdError
from tests.fakes import FakeClock
from tests.fakes_cve import FakeEpss, FakeKev, FakeNvd, InMemoryCveRepository

LOG4J = "CVE-2021-44228"
HEARTBLEED = "CVE-2014-0160"
OLD = "CVE-2010-0001"


class Env:
    def __init__(self, max_lookups: int = 200) -> None:
        self.clock = FakeClock()
        self.repo = InMemoryCveRepository()
        self.nvd = FakeNvd()
        self.epss = FakeEpss()
        self.kev = FakeKev()
        self.sync = SyncCveCatalog(
            self.repo, self.nvd, self.epss, self.kev, self.clock, max_lookups=max_lookups
        )
        self.lookup = LookupCve(self.repo, self.nvd, self.epss, self.kev, self.clock)

    def seed_feeds(self) -> None:
        self.kev.ids = {LOG4J, HEARTBLEED}
        self.nvd.kev_items = [
            NvdCve(LOG4J, 10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            NvdCve(HEARTBLEED, 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        ]
        self.epss.scores = {LOG4J: 0.94358, HEARTBLEED: 0.94212}


async def test_sync_fills_catalog_from_kev_nvd_and_epss() -> None:
    env = Env()
    env.seed_feeds()
    result = await env.sync.execute()
    assert (result.targets, result.changed, result.complete) == (2, 2, True)
    record = env.repo.records[LOG4J]
    assert (record.cvss_score, record.epss_score, record.in_cisa_kev) == (10.0, 0.94358, True)
    assert record.cvss_vector is not None
    assert record.cvss_vector.startswith("CVSS:3.1/")


async def test_sync_is_idempotent() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    snapshot = dict(env.repo.records)
    env.clock.advance(hours=6)
    again = await env.sync.execute()
    assert again.changed == 0
    assert env.repo.records == snapshot


async def test_sync_updates_only_changed_rows() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    env.epss.scores[HEARTBLEED] = 0.5
    env.clock.advance(hours=6)
    result = await env.sync.execute()
    assert result.changed == 1
    assert env.repo.records[HEARTBLEED].epss_score == 0.5
    assert env.repo.records[LOG4J].synced_at < env.repo.records[HEARTBLEED].synced_at


async def test_sync_keeps_catalog_when_nvd_is_down() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    env.nvd.fail_kev = True
    env.nvd.fail_lookup = True
    env.epss.scores[LOG4J] = 0.9
    result = await env.sync.execute(extra_ids=[OLD])
    assert result.nvd_ok is False
    assert result.kev_ok is True
    assert env.repo.records[LOG4J].cvss_score == 10.0
    assert env.repo.records[LOG4J].epss_score == 0.9
    assert OLD not in env.repo.records


async def test_sync_survives_every_feed_down() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    before = dict(env.repo.records)
    env.nvd.fail_kev = env.nvd.fail_lookup = env.epss.fail = env.kev.fail = True
    result = await env.sync.execute()
    assert (result.kev_ok, result.nvd_ok, result.epss_ok, result.changed) == (
        False,
        False,
        False,
        0,
    )
    assert env.repo.records == before


async def test_sync_keeps_existing_epss_and_kev_when_feeds_fail() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    env.epss.fail = True
    env.kev.fail = True
    await env.sync.execute()
    record = env.repo.records[LOG4J]
    assert record.epss_score == 0.94358
    assert record.in_cisa_kev is True


async def test_sync_removes_kev_flag_when_cve_leaves_the_list() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    env.kev.ids.discard(HEARTBLEED)
    env.nvd.kev_items = [i for i in env.nvd.kev_items if i.cve_id != HEARTBLEED]
    await env.sync.execute()
    assert env.repo.records[HEARTBLEED].in_cisa_kev is False


async def test_sync_looks_up_requested_ids_and_respects_the_limit() -> None:
    env = Env(max_lookups=1)
    env.nvd.by_id = {
        OLD: NvdCve(OLD, 4.3, None),
        "CVE-2011-0002": NvdCve("CVE-2011-0002", 5.0, None),
    }
    result = await env.sync.execute(extra_ids=[OLD, "cve-2011-0002"])
    assert result.lookups_skipped == 1
    assert env.nvd.lookups == [OLD]
    assert set(env.repo.records) == {OLD}


async def test_sync_does_not_store_empty_rows() -> None:
    env = Env()
    await env.sync.execute(extra_ids=[OLD])
    assert env.repo.records == {}


async def test_sync_rejects_malformed_requested_ids() -> None:
    env = Env()
    with pytest.raises(InvalidCveIdError):
        await env.sync.execute(extra_ids=["not-a-cve"])


async def test_lookup_returns_stored_record_without_calling_feeds() -> None:
    env = Env()
    env.seed_feeds()
    await env.sync.execute()
    env.nvd.fail_lookup = True
    record = await env.lookup.execute(" cve-2021-44228 ")
    assert record.cve_id == LOG4J
    assert env.nvd.lookups == []


async def test_lookup_fetches_and_stores_missing_cve() -> None:
    env = Env()
    env.nvd.by_id = {OLD: NvdCve(OLD, 6.4, "CVSS:3.1/AV:N")}
    env.epss.scores = {OLD: 0.01234567}
    env.kev.ids = {OLD}
    record = await env.lookup.execute(OLD)
    assert (record.cvss_score, record.epss_score, record.in_cisa_kev) == (6.4, 0.01235, True)
    assert env.repo.records[OLD] == record


async def test_lookup_tolerates_epss_and_kev_failures() -> None:
    env = Env()
    env.nvd.by_id = {OLD: NvdCve(OLD, 6.4, None)}
    env.epss.fail = env.kev.fail = True
    record = await env.lookup.execute(OLD)
    assert (record.cvss_score, record.epss_score, record.in_cisa_kev) == (6.4, None, False)


async def test_lookup_unknown_cve_and_nvd_down() -> None:
    env = Env()
    with pytest.raises(EntityNotFoundError):
        await env.lookup.execute(OLD)
    env.nvd.fail_lookup = True
    with pytest.raises(FeedUnavailableError):
        await env.lookup.execute(OLD)
    with pytest.raises(InvalidCveIdError):
        await env.lookup.execute("nope")
