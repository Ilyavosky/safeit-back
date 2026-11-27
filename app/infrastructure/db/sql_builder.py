from collections.abc import Iterable

from psycopg import sql


def query(template: str, **fragments: str | sql.Composable) -> sql.Composed:
    parts = {
        name: value if isinstance(value, sql.Composable) else sql.SQL(value)
        for name, value in fragments.items()
    }
    return sql.SQL(template).format(**parts)


def conjunction(clauses: Iterable[str]) -> sql.Composable:
    return sql.SQL(" and ").join(sql.SQL(clause) for clause in clauses)
