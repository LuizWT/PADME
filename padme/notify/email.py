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
from .telegram import _DESC, _KIND_LABEL, _KIND_ORDER, _MARK


def _plain_line(e: Event) -> str:
    mark = _MARK[e.event_type]
    desc = _DESC.get(e.kind, {}).get(e.event_type.value, "")
    suffix = f" — {desc}" if desc else ""
    if e.kind == Kind.DNS and "|" in e.key:
        host, rtype, val = (e.key.split("|", 2) + ["", ""])[:3]
        return f"  {mark} {host} {rtype} {val}{suffix}"
    if e.event_type == EventType.CHANGED:
        return f"  {mark} {e.key}{suffix}\n      {e.old_value} -> {e.new_value}"
    if e.event_type == EventType.ADDED and e.new_value and e.kind in (Kind.HTTP, Kind.TAKEOVER, Kind.CERT_EXPIRY):
        return f"  {mark} {e.key}{suffix}\n      {e.new_value}"
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
    def __init__(self, host: str, port: int, username: str, password: str,
                 from_addr: str, to: list[str], use_tls: bool = True, timeout: float = 20.0):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to = to
        self.use_tls = use_tls
        self.timeout = timeout

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

    async def _send(self, subject: str, body: str) -> bool:
        if not self.configured or not body:
            return False
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._send_sync, subject, body)
            return True
        except Exception:
            return False

    async def notify_events(self, target: str, events: list[Event]) -> bool:
        subject = f"[Padmé] {target} — {len(events)} mudança(s)"
        return await self._send(subject, format_events_plain(target, events))

    async def announce(self, msg: str) -> bool:
        return await self._send("[Padmé] status", f"Padmé — {msg}")
