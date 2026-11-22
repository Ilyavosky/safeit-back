from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class EmailMessage:
    to: str
    subject: str
    text: str
    html: str


class Mailer(Protocol):
    async def send(self, message: EmailMessage) -> None: ...
