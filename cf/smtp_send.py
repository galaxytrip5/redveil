# language: Python 3.11+, file: cf/smtp_send.py
# *smtp sending profile — direct delivery through a relay the operator owns*
from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import Any

TLS_MODES = ("starttls", "ssl", "none")
MAX_BODY_CHARS = 20_000


@dataclass(frozen=True, slots=True)
class SmtpProfile:
    """Immutable sending profile — credentials never live here; the
    password is resolved at send time via resolve_secret()."""

    host: str
    port: int = 587
    user: str = ""
    sender: str = ""
    tls: str = "starttls"

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("smtp profile needs a host")
        if self.port < 1 or self.port > 65535:
            raise ValueError("smtp port must be 1..65535")
        if self.tls not in TLS_MODES:
            raise ValueError(f"tls must be one of {TLS_MODES}")

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> SmtpProfile:
        return cls(
            host=str(config.get("host", "")),
            port=int(config.get("port", 587)),
            user=str(config.get("user", "")),
            sender=str(config.get("sender", "")),
            tls=str(config.get("tls", "starttls")),
        )

    def to_config(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "sender": self.sender,
            "tls": self.tls,
        }


def build_message(
    *,
    sender: str,
    to: str,
    subject: str,
    body: str,
    pixel_url: str = "",
) -> EmailMessage:
    """One lure per message: text body plus an html alternative that
    carries the 1x1 open pixel when a pixel URL is supplied."""
    if not sender:
        raise ValueError("sender must not be empty")
    if not to:
        raise ValueError("recipient must not be empty")
    if not body:
        raise ValueError("body must not be empty")
    msg = EmailMessage()
    name, _, addr = str(sender).partition("<")
    display = name.strip()
    addr = (addr or sender).strip("<> ").strip()
    if display:
        msg["From"] = formataddr((display, addr))
    else:
        msg["From"] = addr
    msg["To"] = to
    msg["Subject"] = subject[:255]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    html = body if len(body) <= MAX_BODY_CHARS else body[:MAX_BODY_CHARS]
    if pixel_url:
        html += (
            f'<img src="{pixel_url}" width="1" height="1" alt="" '
            'style="display:none">'
        )
    msg.set_content(body[:MAX_BODY_CHARS])
    msg.add_alternative(
        f"<html><body><p>{html}</p></body></html>", subtype="html"
    )
    return msg


class SmtpSender:
    """Sequential sends over one connection — bounded by the target count,
    a per-message timeout and a hard session ceiling. Failures are values:
    a failed target skips its status flip and is reported, never raised."""

    MAX_PER_SESSION = 500

    def __init__(self, profile: SmtpProfile, password: str = "") -> None:
        self.profile = profile
        self.password = password

    def _connect(self) -> smtplib.SMTP:
        p = self.profile
        timeout = 15.0
        if p.tls == "ssl":
            ctx = ssl.create_default_context()
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                p.host, p.port, timeout=timeout, context=ctx
            )
        else:
            client = smtplib.SMTP(p.host, p.port, timeout=timeout)
            if p.tls == "starttls":
                client.starttls(context=ssl.create_default_context())
        if p.user:
            client.login(p.user, self.password)
        return client

    def send_batch(
        self,
        messages: list[tuple[str, EmailMessage]],
    ) -> dict[str, bool]:
        """Returns {recipient: ok} — one connection, MAX_PER_SESSION ceiling,
        per-message try/except so one bad address never kills the batch."""
        if len(messages) > self.MAX_PER_SESSION:
            raise ValueError(
                f"batch capped at {self.MAX_PER_SESSION} messages per session"
            )
        outcome: dict[str, bool] = {}
        with self._connect() as client:
            for to, msg in messages:
                try:
                    client.send_message(msg, from_addr=self._from_addr())
                    outcome[to] = True
                except (smtplib.SMTPException, OSError):
                    outcome[to] = False
        return outcome

    def _from_addr(self) -> str:
        raw = self.profile.sender or self.profile.user
        _, _, addr = raw.partition("<")
        return (addr or raw).strip("<> ").strip()
