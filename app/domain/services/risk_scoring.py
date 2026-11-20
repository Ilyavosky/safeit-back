CVSS_WEIGHT = 10.0
EPSS_WEIGHT = 20.0
KEV_FLOOR = 90.0
MAX_SCORE = 100.0


def priority_score(cvss: float | None, epss: float | None, in_kev: bool) -> float | None:
    if cvss is None and epss is None and not in_kev:
        return None
    base = _clamp(cvss, 0.0, 10.0) * CVSS_WEIGHT if cvss is not None else 0.0
    exploit = _clamp(epss, 0.0, 1.0) * EPSS_WEIGHT if epss is not None else 0.0
    score = base + exploit
    if in_kev:
        score = max(score, KEV_FLOOR)
    return round(min(score, MAX_SCORE), 2)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(value, high))
