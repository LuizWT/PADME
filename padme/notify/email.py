"""Notificador por e-mail (SMTP).

Envia os alertas (texto puro) por SMTP com STARTTLS. O smtplib é síncrono,
então o envio roda num executor para não travar o loop.
"""

from __future__ import annotations

import asyncio
import smtplib
from datetime import datetime
from email.message import EmailMessage

from ..models import Event, EventType, Kind
from ..risk import Level
from .base import NotificationResult
from .formatting import DESC as _DESC
from .formatting import KIND_LABEL as _KIND_LABEL
from .formatting import KIND_ORDER as _KIND_ORDER
from .formatting import MARK as _MARK
from .formatting import dns_parts
from .formatting import risk_suffix as _risk_suffix


def _plain_line(e: Event) -> str:
    mark = _MARK[e.event_type]
    desc = _DESC.get(e.kind, {}).get(e.event_type.value, "")
    suffix = (f" — {desc}" if desc else "") + _risk_suffix(e)
    if e.kind == Kind.DNS and "|" in e.key:
        host, rtype, val = dns_parts(e)
        return f"  {mark} {host} {rtype} {val}{suffix}"
    if e.event_type == EventType.CHANGED:
        return f"  {mark} {e.key}{suffix}\n      {e.old_value} -> {e.new_value}"
    if e.event_type == EventType.ADDED and e.new_value and e.kind in (Kind.HTTP, Kind.TAKEOVER, Kind.CERT_EXPIRY):
        return f"  {mark} {e.key}{suffix}\n      {e.new_value}"
    if e.kind == Kind.SUBDOMAIN and e.event_type == EventType.ADDED and e.new_value:
        return f"  {mark} {e.key}{suffix} [{e.new_value}]"
    return f"  {mark} {e.key}{suffix}"


def format_events_plain(target: str, events: list[Event], when: datetime | None = None) -> str:
    if not events:
        return ""
    when = when or datetime.now()
    counts = {t: 0 for t in EventType}
    for e in events:
        counts[e.event_type] += 1
    tally = " ".join(f"{_MARK[t]}{counts[t]}" for t in EventType if counts[t])

    lines = [f"PADMÉ · {target}", f"{when:%Y-%m-%d %H:%M} · {tally}"]
    by_kind: dict[Kind, list[Event]] = {}
    for e in events:
        by_kind.setdefault(e.kind, []).append(e)
    for kind in _KIND_ORDER:
        group = by_kind.get(kind)
        if not group:
            continue
        lines.append("")
        lines.append(f"[{_KIND_LABEL.get(kind, kind.value)}]")
        group.sort(key=lambda ev: (ev.event_type.value, ev.key))
        lines.extend(_plain_line(e) for e in group)
    return "\n".join(lines)


class EmailNotifier:
    name = "email"

    def __init__(self, host: str, port: int, username: str, password: str,
                 from_addr: str, to: list[str], use_tls: bool = True,
                 timeout: float = 20.0, level: Level = Level.MEDIUM,
                 max_attempts: int = 2):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to = to
        self.use_tls = use_tls
        self.timeout = timeout
        self.level = level
        self.max_attempts = max_attempts

    @property
    def configured(self) -> bool:
        return bool(self.host and self.from_addr and self.to)

    def _send_sync(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to)
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
            if self.use_tls:
                s.starttls()
            if self.username and self.password:
                s.login(self.username, self.password)
            s.send_message(msg)

    async def _send(self, subject: str, body: str) -> NotificationResult:
        if not self.configured:
            return NotificationResult(self.name, ok=False, error="não configurado")
        if not body:
            return NotificationResult(self.name, ok=True, attempts=0)
        loop = asyncio.get_running_loop()
        last_err: str | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                await loop.run_in_executor(None, self._send_sync, subject, body)
                return NotificationResult(self.name, ok=True, attempts=attempt)
            except smtplib.SMTPAuthenticationError as exc:
                # credencial inválida é permanente -> não insiste
                return NotificationResult(self.name, ok=False, attempts=attempt,
                                          error=type(exc).__name__)
            except Exception as exc:  # noqa: BLE001 — transitório: tenta de novo
                last_err = type(exc).__name__
                if attempt < self.max_attempts:
                    await asyncio.sleep(0.5 * attempt)
        return NotificationResult(self.name, ok=False, attempts=self.max_attempts, error=last_err)

    async def notify_events(self, target: str, events: list[Event]) -> NotificationResult:
        subject = f"[Padmé] {target} — {len(events)} mudança(s)"
        return await self._send(subject, format_events_plain(target, events))

    async def announce(self, msg: str) -> NotificationResult:
        return await self._send("[Padmé] status", f"Padmé — {msg}")
