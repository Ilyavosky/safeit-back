import httpx
import structlog

from app.application.ports.mailer import EmailMessage
from app.domain.errors import MailDeliveryError

log = structlog.get_logger(__name__)

RESEND_URL = "https://api.resend.com/emails"


class ResendMailer:
    def __init__(
        self,
        api_key: str,
        sender: str,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key.strip()
        self._sender = sender
        self._timeout = timeout
        self._transport = transport

    async def send(self, message: EmailMessage) -> None:
        payload = {
            "from": self._sender,
            "to": [message.to],
            "subject": message.subject,
            "text": message.text,
            "html": message.html,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport, follow_redirects=False
            ) as client:
                response = await client.post(
                    RESEND_URL,
                    json=payload,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
        except httpx.TransportError as exc:
            log.warning("mail_transport_error", reason=type(exc).__name__)
            raise MailDeliveryError from exc
        if response.status_code >= 300:
            log.warning("mail_rejected", status=response.status_code, body=response.text[:200])
            raise MailDeliveryError


class NullMailer:
    async def send(self, message: EmailMessage) -> None:
        log.warning("mail_not_configured", subject=message.subject)
