from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveredService:
    port: int
    protocol: str
    name: str | None
    version: str | None
    banner: str | None


@dataclass(frozen=True)
class HttpProbe:
    host: str
    url: str
    http_status: int | None
    technologies: tuple[str, ...]
