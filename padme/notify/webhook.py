"""Notificadores extras: Discord e webhook genérico (JSON).

- DiscordNotifier: posta num Discord Webhook URL (conteúdo em Markdown).
- WebhookNotifier: posta um JSON estruturado num endpoint qualquer
  (feito pra n8n / automações — traz os eventos e um texto pronto).

Reaproveita os mesmos rótulos e descrições do Telegram (fonte única).
"""

from __future__ import annotations

from datetime import datetime

import httpx

from ..levels import severity
from ..models import Event, EventType, Kind
from .telegram import _DESC, _KIND_LABEL, _KIND_ORDER, _MARK


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
        "severity": severity(e).name.lower(),
        "kind": e.kind.value,
        "type": e.event_type.value,
        "key": e.key,
        "old": e.old_value,
        "new": e.new_value,
    }


def _split(text: str, limit: int) -> list[str]:
    if len(text) <= limit:
        return [text]
    chunks, buf = [], ""
    for line in text.split("\n"):
        if len(buf) + len(line) + 1 > limit:
            chunks.append(buf)
            buf = line
        else:
            buf = f"{buf}\n{line}" if buf else line
    if buf:
        chunks.append(buf)
    return chunks


# ── notificadores ──────────────────────────────────────────────────────────
class DiscordNotifier:
    def __init__(self, webhook_url: str, timeout: float = 15.0):
        self.webhook_url = webhook_url
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.webhook_url)

    async def _post_chunks(self, text: str) -> bool:
        if not self.configured or not text:
            return False
        ok = True
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for chunk in _split(text, 1900):  # Discord: limite 2000
                try:
                    r = await client.post(self.webhook_url, json={"content": chunk})
                    r.raise_for_status()
                except Exception:
                    ok = False
        return ok

    async def notify_events(self, target: str, events: list[Event]) -> bool:
        return await self._post_chunks(format_events_md(target, events))

    async def announce(self, msg: str) -> bool:
        return await self._post_chunks(f"**Padmé** — {msg}")


class WebhookNotifier:
    """POST de JSON estruturado (n8n, Zapier, endpoint próprio...)."""

    def __init__(self, url: str, timeout: float = 15.0):
        self.url = url
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.url)

    async def _post(self, payload: dict) -> bool:
        if not self.configured:
            return False
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(self.url, json=payload)
                r.raise_for_status()
            return True
        except Exception:
            return False

    async def notify_events(self, target: str, events: list[Event]) -> bool:
        payload = {
            "source": "padme",
            "type": "changes",
            "target": target,
            "time": datetime.now().isoformat(timespec="seconds"),
            "count": len(events),
            "events": [event_to_dict(e) for e in events],
            "text": format_events_md(target, events),
        }
        return await self._post(payload)

    async def announce(self, msg: str) -> bool:
        return await self._post({
            "source": "padme",
            "type": "announce",
            "time": datetime.now().isoformat(timespec="seconds"),
            "text": msg,
        })
