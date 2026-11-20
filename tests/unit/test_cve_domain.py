import pytest

from app.domain.errors import InvalidCveIdError
from app.domain.services.cve_id import normalize_cve_id
from app.domain.services.risk_scoring import priority_score


@pytest.mark.parametrize(
    ("cvss", "epss", "in_kev", "expected"),
    [
        (None, None, False, None),
        (0.0, 0.0, False, 0.0),
        (5.0, 0.1, False, 52.0),
        (7.5, 0.0, False, 75.0),
        (7.5, None, False, 75.0),
        (9.8, 0.5, False, 100.0),
        (9.8, 1.0, False, 100.0),
        (None, 0.5, False, 10.0),
        (None, 1.0, False, 20.0),
        (None, None, True, 90.0),
        (None, 0.01, True, 90.0),
        (3.0, 0.0, True, 90.0),
        (9.1, 0.02, True, 91.4),
        (9.8, 0.9, True, 100.0),
        (12.0, 2.0, False, 100.0),
        (-1.0, -1.0, False, 0.0),
        (4.3, 0.00123, False, 43.02),
    ],
)
def test_priority_score_table(
    cvss: float | None, epss: float | None, in_kev: bool, expected: float | None
) -> None:
    assert priority_score(cvss, epss, in_kev) == expected


def test_priority_score_is_monotonic_in_each_input() -> None:
    assert priority_score(5.0, 0.2, False) > priority_score(5.0, 0.1, False)  # type: ignore[operator]
    assert priority_score(6.0, 0.1, False) > priority_score(5.0, 0.1, False)  # type: ignore[operator]
    assert priority_score(5.0, 0.1, True) > priority_score(5.0, 0.1, False)  # type: ignore[operator]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2021-44228", "CVE-2021-44228"),
        ("  cve-2014-0160 ", "CVE-2014-0160"),
        ("CVE-2024-123456", "CVE-2024-123456"),
    ],
)
def test_normalize_cve_id_accepts_valid(raw: str, expected: str) -> None:
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "CVE-21-1",
        "CVE-2021-123",
        "CVE-2021-1234;drop",
        "2021-44228",
        "CVE-2021-44228 x",
        "CVE-" + "9" * 30,
    ],
)
def test_normalize_cve_id_rejects_invalid(raw: str) -> None:
    with pytest.raises(InvalidCveIdError):
        normalize_cve_id(raw)
