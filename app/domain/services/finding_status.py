from app.domain.errors import InvalidStatusTransitionError
from app.domain.value_objects.finding_lifecycle import FindingLifecycle
from app.domain.value_objects.job_status import JobStatus
from app.domain.value_objects.remediation_status import RemediationStatus

MIN_REASON_CHARS = 5

_ALLOWED: dict[RemediationStatus, frozenset[RemediationStatus]] = {
    RemediationStatus.OPEN: frozenset({RemediationStatus.IN_PROGRESS, RemediationStatus.FIXED}),
    RemediationStatus.IN_PROGRESS: frozenset({RemediationStatus.OPEN, RemediationStatus.FIXED}),
    RemediationStatus.FIXED: frozenset({RemediationStatus.OPEN, RemediationStatus.IN_PROGRESS}),
}


def lifecycle_status(
    remediation: RemediationStatus,
    is_false_positive: bool,
    scan_status: JobStatus,
    has_report: bool,
) -> FindingLifecycle:
    if is_false_positive:
        return FindingLifecycle.FALSE_POSITIVE
    if remediation is RemediationStatus.FIXED:
        return FindingLifecycle.RESOLVED
    if remediation is RemediationStatus.IN_PROGRESS:
        return FindingLifecycle.IN_REMEDIATION
    if scan_status in (JobStatus.QUEUED, JobStatus.RUNNING):
        return FindingLifecycle.DISCOVERED
    if scan_status is JobStatus.DONE and not has_report:
        return FindingLifecycle.IN_ANALYSIS
    return FindingLifecycle.CONFIRMED


def ensure_transition(
    current: RemediationStatus,
    target: RemediationStatus,
    reason: str | None,
    *,
    is_false_positive: bool,
) -> None:
    if is_false_positive:
        raise InvalidStatusTransitionError("Un falso positivo no admite cambios de estado.")
    if target not in _ALLOWED[current]:
        raise InvalidStatusTransitionError(
            f"No se puede pasar de «{current.value}» a «{target.value}»."
        )
    if current is RemediationStatus.FIXED and len((reason or "").strip()) < MIN_REASON_CHARS:
        raise InvalidStatusTransitionError(
            "Reabrir un hallazgo resuelto requiere un motivo de al menos 5 caracteres."
        )
