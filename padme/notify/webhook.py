"""Notificadores extras: Discord e webhook genérico (JSON).

- DiscordNotifier: posta num Discord Webhook URL (conteúdo em Markdown).
- WebhookNotifier: posta um JSON estruturado num endpoint qualquer
  (feito pra n8n / automações — traz os eventos e um texto pronto).

Reaproveita os mesmos rótulos e descrições do Telegram (fonte única).
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from ..levels import Level, severity
from ..models import Event, EventType, Kind
from .base import NotificationResult, chunk_text, post_with_retry
from .formatting import DESC as _DESC
from .formatting import KIND_LABEL as _KIND_LABEL
from .formatting import KIND_ORDER as _KIND_ORDER
from .formatting import MARK as _MARK

# Versão do contrato JSON do webhook genérico (consumidores tipo n8n).
WEBHOOK_SCHEMA_VERSION = 1


# ── formatação Markdown (Discord) ──────────────────────────────────────────
def _md_key(e: Event) -> str:
    # Discord auto-linka URL nua; host fica em `code`
    if e.kind == Kind.HTTP and e.key.startswith(("http://", "https://")):
        return e.key
    return f"`{e.key}`"


def _md_desc(e: Event) -> str:
    d = _DESC.get(e.kind, {}).get(e.event_type.value, "")
    return f" — {d}" if d else ""


def _md_line(e: Event) -> str:
    mark = _MARK[e.event_type]
    if e.kind == Kind.DNS and "|" in e.key:
        host, rtype, val = (e.key.split("|", 2) + ["", ""])[:3]
        return f"{mark} `{host}` {rtype} `{val}`{_md_desc(e)}"
    if e.event_type == EventType.CHANGED:
        return f"{mark} {_md_key(e)}{_md_desc(e)}\n    {e.old_value} → {e.new_value}"
    if e.event_type == EventType.ADDED and e.new_value and e.kind in (Kind.HTTP, Kind.TAKEOVER, Kind.CERT_EXPIRY, Kind.WILDCARD):
        return f"{mark} {_md_key(e)}{_md_desc(e)}\n    {e.new_value}"
    if e.kind == Kind.SUBDOMAIN and e.event_type == EventType.ADDED and e.new_value:
        return f"{mark} {_md_key(e)}{_md_desc(e)} [{e.new_value}]"
    return f"{mark} {_md_key(e)}{_md_desc(e)}"


def format_events_md(target: str, events: list[Event], when: datetime | None = None) -> str:
    if not events:
        return ""
    when = when or datetime.now()
    counts = {t: 0 for t in EventType}
    for e in events:
        counts[e.event_type] += 1
    tally = " ".join(f"{_MARK[t]}{counts[t]}" for t in EventType if counts[t])

    lines = [f"**PADMÉ** · `{target}`", f"`{when:%Y-%m-%d %H:%M}` · `{tally}`"]
    by_kind: dict[Kind, list[Event]] = {}
    for e in events:
        by_kind.setdefault(e.kind, []).append(e)
    for kind in _KIND_ORDER:
        group = by_kind.get(kind)
        if not group:
            continue
        lines.append("")
        lines.append(f"**{_KIND_LABEL.get(kind, kind.value)}**")
        group.sort(key=lambda ev: (ev.event_type.value, ev.key))
        lines.extend(_md_line(e) for e in group)
    return "\n".join(lines)


def event_to_dict(e: Event) -> dict:
    return {
        "event_id": e.event_id,
        "scan_id": e.scan_id,
        "detected_at": e.detected_at,
        "severity": severity(e).name.lower(),
        "kind": e.kind.value,          # collector de origem
        "type": e.event_type.value,
        "key": e.key,
        "old": e.old_value,
        "new": e.new_value,
        "metadata": e.metadata or {},
    }


# ── notificadores ──────────────────────────────────────────────────────────
class DiscordNotifier:
    name = "discord"

    def __init__(self, webhook_url: str, timeout: float = 15.0, level: Level = Level.MEDIUM):
        self.webhook_url = webhook_url
        self.timeout = timeout
        self.level = level

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    async def _post_chunks(self, text: str) -> NotificationResult:
        if not self.configured:
            return NotificationResult(self.name, ok=False, error="não configurado")
        if not text:
            return NotificationResult(self.name, ok=True, attempts=0)
        attempts = 0
        last: NotificationResult | None = None
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for chunk in chunk_text(text, 1900):  # Discord: limite 2000
                r = await post_with_retry(client, self.webhook_url, self.name,
                                          json={"content": chunk})
                attempts += r.attempts
                last = r
                if not r.ok:
                    return NotificationResult(self.name, ok=False, attempts=attempts,
                                              status=r.status, error=r.error)
        return NotificationResult(self.name, ok=True, attempts=attempts,
                                  status=last.status if last else None)

    async def notify_events(self, target: str, events: list[Event]) -> NotificationResult:
        return await self._post_chunks(format_events_md(target, events))

    async def announce(self, msg: str) -> NotificationResult:
        return await self._post_chunks(f"**Padmé** — {msg}")


class WebhookNotifier:
    """POST de JSON estruturado (n8n, Zapier, endpoint próprio...).

    Suporta headers opcionais (ex.: um token de auth) para endpoints próprios.
    """

    name = "webhook"

    def __init__(self, url: str, timeout: float = 15.0, level: Level = Level.DEBUG,
                 headers: dict[str, str] | None = None):
        self.url = url
        self.timeout = timeout
        self.level = level
        self.headers = headers or {}

    @property
    def configured(self) -> bool:
        return bool(self.url)

    async def _post(self, payload: dict) -> NotificationResult:
        if not self.configured:
            return NotificationResult(self.name, ok=False, error="não configurado")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            return await post_with_retry(client, self.url, self.name, json=payload,
                                         headers=self.headers or None)

    async def notify_events(self, target: str, events: list[Event]) -> NotificationResult:
        scan_id = next((e.scan_id for e in events if e.scan_id), None)
        payload = {
            "schema_version": WEBHOOK_SCHEMA_VERSION,
            "source": "padme",
            "type": "changes",
            "target": target,
            "scan_id": scan_id,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "count": len(events),
            "events": [event_to_dict(e) for e in events],
            "text": format_events_md(target, events),
        }
        return await self._post(payload)

    async def announce(self, msg: str) -> NotificationResult:
        return await self._post({
            "schema_version": WEBHOOK_SCHEMA_VERSION,
            "source": "padme",
            "type": "announce",
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "text": msg,
        })
