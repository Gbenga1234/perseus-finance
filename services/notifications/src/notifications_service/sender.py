from __future__ import annotations

import ssl
from email.message import EmailMessage
from email.utils import make_msgid
from typing import Protocol

import aiosmtplib
from perseus_common.config import normalize_pem

from notifications_service.config import Settings


class EmailSender(Protocol):
    async def send(self, to: str, subject: str, body: str) -> None: ...


class SmtpEmailSender:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._tls_context: ssl.SSLContext | None = None
        if settings.smtp_ca_pem:
            # Verifies the relay against our private CA (hostname checking stays on).
            self._tls_context = ssl.create_default_context(
                cadata=normalize_pem(settings.smtp_ca_pem)
            )

    async def send(self, to: str, subject: str, body: str) -> None:
        s = self._settings
        message = EmailMessage()
        message["From"] = s.mail_from
        message["To"] = to
        message["Subject"] = subject
        message["Message-ID"] = make_msgid(domain="perseus.local")
        message.set_content(body)
        await aiosmtplib.send(
            message,
            hostname=s.smtp_host,
            port=s.smtp_port,
            username=s.smtp_username,
            password=s.smtp_password.get_secret_value() if s.smtp_password else None,
            start_tls=s.smtp_starttls,
            use_tls=s.smtp_use_tls,
            timeout=s.smtp_timeout_seconds,
            cert_bundle=None if self._tls_context else s.smtp_ca_file,
            tls_context=self._tls_context,
            local_hostname=s.smtp_helo_hostname,
        )
