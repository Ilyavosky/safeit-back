from dataclasses import dataclass

from app.application.ports.database import DatabasePort
from app.config import Settings
from app.infrastructure.db.session import PostgresDatabase


@dataclass(frozen=True)
class Container:
    settings: Settings
    database: DatabasePort


def build_container(settings: Settings) -> Container:
    database = PostgresDatabase(
        dsn=settings.database_url.get_secret_value(),
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
    )
    return Container(settings=settings, database=database)
