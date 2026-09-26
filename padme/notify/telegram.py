"""Notificação via Telegram Bot API.

Setup rápido:
  1. Fale com @BotFather no Telegram -> /newbot -> pegue o BOT TOKEN.
  2. Descubra seu chat_id: mande uma msg pro bot e acesse
     https://api.telegram.org/bot<TOKEN>/getUpdates  (campo chat.id)
     — ou use @userinfobot.
  3. Coloque token e chat_id no config (ou em variáveis de ambiente).
"""

from __future__ import annotations

import html
from datetime import datetime

import httpx

from ..levels import Level
from ..models import Event, EventType, Kind
from .base import NotificationResult, chunk_text, post_with_retry
from .formatting import DESC as _DESC
from .formatting import KIND_LABEL as _KIND_LABEL
from .formatting import KIND_ORDER as _KIND_ORDER
from .formatting import MARK as _MARK


def _esc(s: str | None) -> str:
    return html.escape(s or "")


def _key_html(e: Event) -> str:
    # URLs viram link clicável; o resto fica em <code> (copiável, e link não combina com code)
    if e.kind == Kind.HTTP and e.key.startswith(("http://", "https://")):
        return f'<a href="{_esc(e.key)}">{_esc(e.key)}</a>'
    return f"<code>{_esc(e.key)}</code>"


def _desc(e: Event) -> str:
    d = _DESC.get(e.kind, {}).get(e.event_type.value, "")
    return f" — {d}" if d else ""


def _event_line(e: Event) -> str:
    """marker + alvo + descrição técnica curta; detalhe na linha seguinte."""
    mark = _MARK[e.event_type]

    if e.kind == Kind.DNS and "|" in e.key:
        host, rtype, val = (e.key.split("|", 2) + ["", ""])[:3]
        return f"{mark} <code>{_esc(host)}</code> {_esc(rtype)} <code>{_esc(val)}</code>{_desc(e)}"

    if e.event_type == EventType.CHANGED:
        return f"{mark} {_key_html(e)}{_desc(e)}\n    {_esc(e.old_value)} <b>→</b> {_esc(e.new_value)}"

    if e.event_type == EventType.ADDED and e.new_value and e.kind in (Kind.HTTP, Kind.TAKEOVER, Kind.CERT_EXPIRY, Kind.WILDCARD):
        return f"{mark} {_key_html(e)}{_desc(e)}\n    {_esc(e.new_value)}"

    if e.kind == Kind.SUBDOMAIN and e.event_type == EventType.ADDED and e.new_value:
        return f"{mark} {_key_html(e)}{_desc(e)} [{_esc(e.new_value)}]"

    return f"{mark} {_key_html(e)}{_desc(e)}"


def format_events(target: str, events: list[Event], when: datetime | None = None) -> str:
    """Monta a mensagem (parse_mode HTML do Telegram).

    Saída estilo diff: cabeçalho + corpo por categoria dentro de um
    <blockquote expandable>. Alerta curto aparece completo; longo chega
    recolhido.
    """
    if not events:
        return ""
    when = when or datetime.now()

    counts = {t: 0 for t in EventType}
    for e in events:
        counts[e.event_type] += 1
    tally = " ".join(
        f"{_MARK[t]}{counts[t]}" for t in EventType if counts[t]
    )

    header = [
        f"<b>PADMÉ</b> · <code>{_esc(target)}</code>",
        f"<code>{when:%Y-%m-%d %H:%M}</code> · <code>{tally}</code>",
    ]

    by_kind: dict[Kind, list[Event]] = {}
    for e in events:
        by_kind.setdefault(e.kind, []).append(e)

    body: list[str] = []
    for kind in _KIND_ORDER:
        group = by_kind.get(kind)
        if not group:
            continue
        if body:
            body.append("")
        body.append(f"<b>{_KIND_LABEL.get(kind, kind.value)}</b>")
        group.sort(key=lambda ev: (ev.event_type.value, ev.key))
        body.extend(_event_line(e) for e in group)

    return "\n".join(header + [f"<blockquote expandable>{chr(10).join(body)}</blockquote>"])


class TelegramNotifier:
    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str, timeout: float = 15.0,
                 level: Level = Level.MEDIUM):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout = timeout
        self.level = level

    @property
    def configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    async def send(self, text: str) -> NotificationResult:
        if not self.configured:
            return NotificationResult(self.name, ok=False, error="não configurado")
        if not text:
            return NotificationResult(self.name, ok=True, attempts=0)
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        attempts = 0
        last: NotificationResult | None = None
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for chunk in chunk_text(text, 3900):  # Telegram corta em 4096
                r = await post_with_retry(
                    client, url, self.name,
                    json={
                        "chat_id": self.chat_id,
                        "text": chunk,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True,
                    },
                )
                attempts += r.attempts
                last = r
                if not r.ok:
                    return NotificationResult(self.name, ok=False, attempts=attempts,
                                              status=r.status, error=r.error)
        return NotificationResult(self.name, ok=True, attempts=attempts,
                                  status=last.status if last else None)

    async def notify_events(self, target: str, events: list[Event]) -> NotificationResult:
        return await self.send(format_events(target, events))

    async def announce(self, msg: str) -> NotificationResult:
        return await self.send(f"🛰️ <b>Padmé</b> — {_esc(msg)}")
