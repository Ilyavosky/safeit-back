import ast
from pathlib import Path

DB_DIR = Path(__file__).resolve().parents[2] / "app" / "infrastructure" / "db"

SAFE_INTERPOLATIONS = {
    "_COLUMNS",
    "_ASSET",
    "_ENDPOINT",
    "_SELECT",
    "_FROM",
    "_LIFECYCLE",
    "_HOST_COLUMNS",
    "_REC_COLUMNS",
    "where",
    "key",
    "expr",
    "cast",
    "key.replace('::text', '')",
    "' and '.join(clauses)",
    "' and '.join(conditions)",
}
SQL_WORDS = ("select ", "insert ", "update ", "delete ", "where ", " from ", "order by", "group by")


def _looks_like_sql(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and any(word in node.value.lower() for word in SQL_WORDS)
    )


def _sources() -> list[Path]:
    return sorted(path for path in DB_DIR.glob("*.py") if path.name != "__init__.py")


def test_only_reviewed_fragments_are_interpolated_into_sql() -> None:
    unexpected: list[str] = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            literal = "".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            ).lower()
            if not any(word in literal for word in SQL_WORDS):
                continue
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    expression = ast.unparse(part.value)
                    if expression not in SAFE_INTERPOLATIONS:
                        unexpected.append(f"{path.name}:{node.lineno} {{{expression}}}")
    assert not unexpected, (
        "Interpolacion nueva en SQL; usa parametros (%s) o revisa y agrega el fragmento "
        f"constante a SAFE_INTERPOLATIONS: {unexpected}"
    )


def test_sql_is_never_built_with_percent_format_concat_or_format_call() -> None:
    offenders: list[str] = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, (ast.Mod, ast.Add))
                and (_looks_like_sql(node.left) or _looks_like_sql(node.right))
            ):
                offenders.append(f"{path.name}:{node.lineno}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and _looks_like_sql(node.func.value)
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"SQL armado con %, + o format en: {offenders}"


def test_execute_never_receives_a_bare_variable_built_elsewhere() -> None:
    offenders: list[str] = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
                and isinstance(node.args[0], ast.Call)
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"execute() con SQL generado por una llamada: {offenders}"
