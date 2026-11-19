from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.domain.errors import FeedUnavailableError
from app.infrastructure.feeds.epss_client import EpssClient
from app.infrastructure.feeds.http import MinIntervalLimiter, RetryingJsonClient
from app.infrastructure.feeds.kev_client import KevClient
from app.infrastructure.feeds.nvd_client import NvdClient

Handler = Callable[[httpx.Request], httpx.Response]


class Sleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _http(
    handler: Handler, sleeper: Sleeper | None = None, attempts: int = 4
) -> RetryingJsonClient:
    return RetryingJsonClient(
        transport=httpx.MockTransport(handler),
        sleep=sleeper or Sleeper(),
        max_attempts=attempts,
        backoff_seconds=1.0,
    )


def _nvd(handler: Handler, api_key: str | None = None) -> NvdClient:
    sleeper = Sleeper()
    return NvdClient(
        _http(handler, sleeper),
        api_key=api_key,
        limiter=MinIntervalLimiter(0.0, sleep=sleeper),
    )


def _cve(cve_id: str, **metrics: Any) -> dict[str, Any]:
    return {"cve": {"id": cve_id, "metrics": metrics}}


def _metric(score: float, vector: str, kind: str = "Primary") -> dict[str, Any]:
    return {"type": kind, "cvssData": {"baseScore": score, "vectorString": vector}}


async def test_retries_server_errors_with_backoff_then_succeeds() -> None:
    answers = iter([503, 502, 200])

    def handler(request: httpx.Request) -> httpx.Response:
        status = next(answers)
        return httpx.Response(status, json={"ok": True})

    sleeper = Sleeper()
    assert await _http(handler, sleeper).get_json("https://feed.test/x") == {"ok": True}
    assert sleeper.calls == [1.0, 2.0]


async def test_honours_retry_after_and_caps_it() -> None:
    answers = iter([(429, "3"), (429, "9999"), (200, None)])

    def handler(request: httpx.Request) -> httpx.Response:
        status, retry = next(answers)
        headers = {"Retry-After": retry} if retry else {}
        return httpx.Response(status, headers=headers, json={})

    sleeper = Sleeper()
    await _http(handler, sleeper).get_json("https://feed.test/x")
    assert sleeper.calls == [3.0, 60.0]


async def test_gives_up_after_the_last_attempt() -> None:
    hits: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(1)
        return httpx.Response(503)

    with pytest.raises(FeedUnavailableError):
        await _http(handler, attempts=3).get_json("https://feed.test/x")
    assert len(hits) == 3


async def test_does_not_retry_client_errors_or_invalid_json() -> None:
    hits: list[int] = []

    def not_found(request: httpx.Request) -> httpx.Response:
        hits.append(1)
        return httpx.Response(404)

    with pytest.raises(FeedUnavailableError):
        await _http(not_found).get_json("https://feed.test/x")
    assert len(hits) == 1

    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>rate limited</html>")

    with pytest.raises(FeedUnavailableError):
        await _http(garbage).get_json("https://feed.test/x")


async def test_network_errors_are_retried_and_reported_as_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sin red")

    sleeper = Sleeper()
    with pytest.raises(FeedUnavailableError):
        await _http(handler, sleeper, attempts=3).get_json("https://feed.test/x")
    assert sleeper.calls == [1.0, 2.0]


async def test_limiter_spaces_requests() -> None:
    now = [100.0]
    sleeper = Sleeper()

    async def sleep(seconds: float) -> None:
        await sleeper(seconds)
        now[0] += seconds

    limiter = MinIntervalLimiter(6.0, clock=lambda: now[0], sleep=sleep)
    await limiter.wait()
    now[0] += 2.0
    await limiter.wait()
    await limiter.wait()
    assert sleeper.calls == [4.0, 6.0]


async def test_nvd_paginates_kev_results_and_prefers_primary_v31() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        start = int(request.url.params["startIndex"])
        assert "hasKev" in str(request.url)
        if start == 0:
            items = [
                _cve(
                    "CVE-2021-44228",
                    cvssMetricV31=[
                        _metric(5.0, "CVSS:3.1/secondary", "Secondary"),
                        _metric(10.0, "CVSS:3.1/primary"),
                    ],
                    cvssMetricV2=[_metric(9.3, "AV:N")],
                ),
                _cve("CVE-2014-0160", cvssMetricV2=[_metric(5.0, "AV:N/AC:L")]),
            ]
        else:
            items = [_cve("CVE-2010-0001"), {"cve": {"id": "garbage"}}]
        return httpx.Response(200, json={"totalResults": 4, "vulnerabilities": items})

    found = [item async for item in _nvd(handler).iter_kev_cves()]
    assert [(i.cve_id, i.cvss_score, i.cvss_vector) for i in found] == [
        ("CVE-2021-44228", 10.0, "CVSS:3.1/primary"),
        ("CVE-2014-0160", 5.0, "AV:N/AC:L"),
        ("CVE-2010-0001", None, None),
    ]
    assert len(seen) == 2
    assert "startIndex=2" in seen[1]


async def test_nvd_sends_api_key_only_when_configured() -> None:
    headers: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(dict(request.headers))
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    await _nvd(handler).get_cve("CVE-2021-44228")
    await _nvd(handler, api_key="secreta").get_cve("CVE-2021-44228")
    assert "apikey" not in headers[0]
    assert headers[1]["apikey"] == "secreta"


async def test_nvd_get_cve_found_and_missing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params["cveId"] == "CVE-2021-44228":
            body = {
                "totalResults": 1,
                "vulnerabilities": [_cve("CVE-2021-44228", cvssMetricV31=[_metric(10.0, "v")])],
            }
        else:
            body = {"totalResults": 0, "vulnerabilities": []}
        return httpx.Response(200, json=body)

    client = _nvd(handler)
    found = await client.get_cve("cve-2021-44228")
    assert found is not None
    assert found.cvss_score == 10.0
    assert await client.get_cve("CVE-2000-0001") is None


async def test_nvd_rejects_unexpected_payloads() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["no", "es", "un", "objeto"])

    with pytest.raises(FeedUnavailableError):
        await _nvd(handler).get_cve("CVE-2021-44228")


async def test_epss_batches_requests_and_parses_string_scores() -> None:
    requested: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        ids = request.url.params["cve"].split(",")
        requested.append(ids)
        rows = [
            {"cve": i, "epss": "0.012340000", "percentile": "0.5", "date": "2026-01-01"}
            for i in ids[:-1]
        ]
        return httpx.Response(200, json={"status": "OK", "data": rows})

    ids = [f"CVE-2020-{n:04d}" for n in range(1, 251)]
    scores = await EpssClient(_http(handler)).get_scores(ids)
    assert [len(batch) for batch in requested] == [100, 100, 50]
    assert scores["CVE-2020-0001"] == 0.01234
    assert "CVE-2020-0100" not in scores
    assert await EpssClient(_http(handler)).get_scores([]) == {}


async def test_epss_rejects_unexpected_payload() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ERROR"})

    with pytest.raises(FeedUnavailableError):
        await EpssClient(_http(handler)).get_scores(["CVE-2021-44228"])


async def test_kev_parses_ids_and_caches() -> None:
    hits: list[int] = []
    now = [0.0]

    def handler(request: httpx.Request) -> httpx.Response:
        hits.append(1)
        body = {
            "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "cve-2014-0160 "}, {"x": 1}]
        }
        return httpx.Response(200, json=body)

    client = KevClient(_http(handler), clock=lambda: now[0], cache_seconds=60)
    assert await client.list_cve_ids() == {"CVE-2021-44228", "CVE-2014-0160"}
    now[0] = 30.0
    await client.list_cve_ids()
    assert len(hits) == 1
    now[0] = 61.0
    await client.list_cve_ids()
    assert len(hits) == 2


async def test_kev_rejects_unexpected_payload() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": "no"})

    with pytest.raises(FeedUnavailableError):
        await KevClient(_http(handler)).list_cve_ids()
