from collections.abc import Mapping, Sequence

from app.domain.value_objects.severity import Severity

SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
SEVERITY_LABELS = {
    Severity.CRITICAL: "críticos",
    Severity.HIGH: "altos",
    Severity.MEDIUM: "medios",
    Severity.LOW: "bajos",
    Severity.INFO: "informativos",
}


def severity_counts(severities: Sequence[Severity]) -> dict[Severity, int]:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for severity in severities:
        counts[severity] += 1
    return counts


def fallback_summary(domain: str, counts: Mapping[Severity, int]) -> str:
    total = sum(counts.values())
    if total == 0:
        return f"No se registraron hallazgos activos en {domain} durante las pruebas controladas."
    parts = [f"{counts[s]} {SEVERITY_LABELS[s]}" for s in SEVERITY_ORDER if counts[s]]
    return (
        f"Las pruebas controladas sobre {domain} registraron {total} hallazgos activos: "
        f"{', '.join(parts)}. Se recomienda atender primero los de mayor prioridad."
    )


def fallback_action(title: str, url: str) -> str:
    return f"Revisar y corregir «{title}» en {url}."


def build_content(summary: str, actions: Sequence[tuple[int, str]]) -> str:
    lines = ["## Resumen ejecutivo", "", summary, "", "## Recomendaciones", ""]
    if not actions:
        lines.append("Sin recomendaciones pendientes.")
    lines.extend(f"{priority}. {action}" for priority, action in actions)
    return "\n".join(lines) + "\n"
