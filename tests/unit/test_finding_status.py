from uuid import uuid4

import pytest

from app.application.pagination import clamp_limit, decode_cursor, encode_cursor
from app.domain.errors import InvalidCursorError, InvalidStatusTransitionError
from app.domain.services.finding_status import ensure_transition, lifecycle_status
from app.domain.value_objects.finding_lifecycle import FindingLifecycle
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus as R

VALID = [
    (R.OPEN, R.IN_PROGRESS, None),
    (R.OPEN, R.FIXED, None),
    (R.IN_PROGRESS, R.OPEN, None),
    (R.IN_PROGRESS, R.FIXED, None),
    (R.FIXED, R.OPEN, "volvió a aparecer"),
    (R.FIXED, R.IN_PROGRESS, "el parche falló"),
]


@pytest.mark.parametrize(("current", "target", "reason"), VALID)
def test_valid_transitions(current: R, target: R, reason: str | None) -> None:
    ensure_transition(current, target, reason, is_false_positive=False)


@pytest.mark.parametrize(
    ("current", "target", "reason"),
    [
        (R.FIXED, R.OPEN, None),
        (R.FIXED, R.OPEN, "   "),
        (R.FIXED, R.OPEN, "ya"),
        (R.OPEN, R.OPEN, None),
        (R.FIXED, R.FIXED, "motivo largo"),
    ],
)
def test_invalid_transitions(current: R, target: R, reason: str | None) -> None:
    with pytest.raises(InvalidStatusTransitionError):
        ensure_transition(current, target, reason, is_false_positive=False)


def test_false_positives_are_frozen() -> None:
    with pytest.raises(InvalidStatusTransitionError):
        ensure_transition(R.OPEN, R.FIXED, "ok ok ok", is_false_positive=True)


@pytest.mark.parametrize(
    ("remediation", "fp", "scan", "report", "expected"),
    [
        (R.OPEN, True, JobStatus.DONE, True, FindingLifecycle.FALSE_POSITIVE),
        (R.FIXED, False, JobStatus.DONE, True, FindingLifecycle.RESOLVED),
        (R.IN_PROGRESS, False, JobStatus.DONE, True, FindingLifecycle.IN_REMEDIATION),
        (R.OPEN, False, JobStatus.RUNNING, False, FindingLifecycle.DISCOVERED),
        (R.OPEN, False, JobStatus.QUEUED, False, FindingLifecycle.DISCOVERED),
        (R.OPEN, False, JobStatus.DONE, False, FindingLifecycle.IN_ANALYSIS),
        (R.OPEN, False, JobStatus.DONE, True, FindingLifecycle.CONFIRMED),
        (R.OPEN, False, JobStatus.FAILED, False, FindingLifecycle.CONFIRMED),
    ],
)
def test_lifecycle_is_derived(
    remediation: R, fp: bool, scan: JobStatus, report: bool, expected: FindingLifecycle
) -> None:
    assert lifecycle_status(remediation, fp, scan, report) is expected


def test_cursor_round_trip_and_rejection() -> None:
    item = uuid4()
    assert decode_cursor(encode_cursor("45.0", item)) == ("45.0", item)
    for bad in ("###", "e30=", encode_cursor("x", item)[:-6], "bnVsbA=="):
        with pytest.raises(InvalidCursorError):
            decode_cursor(bad)


def test_limit_is_clamped() -> None:
    assert clamp_limit(None) == 25
    assert clamp_limit(0) == 1
    assert clamp_limit(10_000) == 100
