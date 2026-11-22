import json

import httpx
import pytest

from app.application.ports.mailer import EmailMessage
from app.domain.errors import MailDeliveryError
from app.infrastructure.mail.resend_mailer import ResendMailer

MESSAGE = EmailMessage(to="ana@example.com", subject="Asunto", text="texto", html="<p>html</p>")


async def test_sends_expected_payload_with_bearer_key() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"id": "abc"})

    mailer = ResendMailer(
        " re_key \n", "SafeIT <no-reply@ilyacori.com>", transport=httpx.MockTransport(handler)
    )

    await mailer.send(MESSAGE)

    assert seen["url"] == "https://api.resend.com/emails"
    assert seen["auth"] == "Bearer re_key"
    assert seen["body"] == {
        "from": "SafeIT <no-reply@ilyacori.com>",
        "to": ["ana@example.com"],
        "subject": "Asunto",
        "text": "texto",
        "html": "<p>html</p>",
    }


async def test_rejected_by_provider_raises_delivery_error() -> None:
    mailer = ResendMailer(
        "k", "a@b.co", transport=httpx.MockTransport(lambda r: httpx.Response(403, json={}))
    )

    with pytest.raises(MailDeliveryError):
        await mailer.send(MESSAGE)


async def test_network_failure_raises_delivery_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sin red")

    mailer = ResendMailer("k", "a@b.co", transport=httpx.MockTransport(handler))

    with pytest.raises(MailDeliveryError):
        await mailer.send(MESSAGE)
