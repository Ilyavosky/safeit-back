import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[2] / "app"

ALLOWED = {
    "domain": {"app.domain"},
    "application": {"app.domain", "app.application"},
}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def _violations(layer: str) -> list[str]:
    bad: list[str] = []
    for path in (APP / layer).rglob("*.py"):
        for module in _imports(path):
            if module.startswith("app.") and not any(
                module == allowed or module.startswith(allowed + ".") for allowed in ALLOWED[layer]
            ):
                bad.append(f"{path.relative_to(APP)} importa {module}")
    return bad


def test_domain_does_not_import_other_layers() -> None:
    assert _violations("domain") == []


def test_application_only_imports_domain() -> None:
    assert _violations("application") == []
