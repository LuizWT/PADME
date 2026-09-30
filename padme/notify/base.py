"""Contrato e utilidades comuns dos notificadores.

- `NotificationResult`: resultado estruturado de um envio (canal, sucesso,
  tentativas, status HTTP, erro SEGURO — sem segredo).
- `post_with_retry`: POST com retry (só em transitório/429/5xx), backoff com
  jitter e respeito ao `Retry-After`. Nunca faz retry de 4xx permanente.
- `send_all`: despacha os eventos para todos os canais CONCORRENTEMENTE, cada
  um aplicando o SEU próprio limiar de severidade (política por canal). Um canal
  lento ou com falha não bloqueia nem derruba os outros.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import httpx

from ..levels import Level, filter_events
from ..logredact import redact
from ..models import Event

log = logging.getLogger("padme")

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 0.5
_BACKOFF_CAP = 8.0


def chunk_text(text: str, limit: int) -> list[str]:
    """Quebra `text` em pedaços com `len(chunk) <= limit`, garantidamente.

    Prefere quebrar em fronteira de linha; uma linha isolada maior que `limit`
    é cortada de forma determinística. Nunca devolve chunk vazio. Texto vazio
    -> lista vazia (nada a enviar)."""
    if limit <= 0:
        raise ValueError("limit deve ser > 0")
    if not text:
        return []
    chunks: list[str] = []
    buf = ""

    def flush() -> None:
        nonlocal buf
        if buf:
            chunks.append(buf)
            buf = ""

    for line in text.split("\n"):
        while len(line) > limit:  # linha gigante: corta em pedaços do tamanho do limite
            flush()
            chunks.append(line[:limit])
            line = line[limit:]
        candidate = line if not buf else buf + "\n" + line
        if len(candidate) > limit:
            flush()
            buf = line
        else:
            buf = candidate
    flush()
    return chunks


@dataclass
class NotificationResult:
    channel: str
    ok: bool
    attempts: int = 0
    status: int | None = None
    error: str | None = None

    def __bool__(self) -> bool:  # compat: `if await n.notify_events(...)`
        return self.ok


@runtime_checkable
class Notifier(Protocol):
    """Contrato dos canais (formaliza o que já era implícito).

    Todo notifier tem `name`, `level` (limiar próprio) e sabe se está
    `configured`; envia eventos ou um anúncio devolvendo um NotificationResult.
    """

    name: str
    level: Level

    @property
    def configured(self) -> bool: ...

    async def notify_events(self, target: str, events: list[Event]) -> "NotificationResult": ...

    async def announce(self, msg: str) -> "NotificationResult": ...


def _backoff(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return min(retry_after, 30.0)
    return min(_BACKOFF_CAP, _BACKOFF_BASE * (2 ** (attempt - 1))) + random.uniform(0, 0.25)


def _retry_after(resp: httpx.Response) -> float | None:
    val = resp.headers.get("retry-after")
    if not val:
        return None
    try:
        return float(val)  # forma em segundos (a data HTTP é ignorada, backoff cobre)
    except ValueError:
        return None


async def post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    channel: str,
    *,
    json: dict | None = None,
    content: str | bytes | None = None,
    headers: dict[str, str] | None = None,
    max_attempts: int = _MAX_ATTEMPTS,
) -> NotificationResult:
    """POST resiliente. Retry só em timeout/erro de conexão/429/5xx."""
    last_status: int | None = None
    last_err: str | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            resp = await client.post(url, json=json, content=content, headers=headers)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_err = type(exc).__name__  # sem detalhe -> não vaza URL/segredo
            if attempt < max_attempts:
                await asyncio.sleep(_backoff(attempt, None))
                continue
            return NotificationResult(channel, ok=False, attempts=attempt, error=last_err)

        last_status = resp.status_code
        if resp.status_code < 400:
            return NotificationResult(channel, ok=True, attempts=attempt, status=resp.status_code)
        if resp.status_code in _RETRY_STATUSES and attempt < max_attempts:
            await asyncio.sleep(_backoff(attempt, _retry_after(resp)))
            continue
        # 4xx permanente (400/401/403/404...) ou 5xx esgotado
        return NotificationResult(channel, ok=False, attempts=attempt, status=resp.status_code,
                                  error=f"HTTP {resp.status_code}")
    return NotificationResult(channel, ok=False, attempts=max_attempts,
                              status=last_status, error=last_err or "falha")


async def send_all(notifiers: list, target: str, events: list[Event]) -> list["NotificationResult"]:
    """Despacha os eventos a TODOS os canais em paralelo, cada um filtrando pelo
    seu próprio nível. Devolve um NotificationResult por canal."""
    async def one(n) -> NotificationResult:
        level: Level = getattr(n, "level", Level.MEDIUM)
        chosen = filter_events(events, level)
        if not chosen:
            return NotificationResult(getattr(n, "name", type(n).__name__), ok=True, attempts=0)
        return await n.notify_events(target, chosen)

    raw = await asyncio.gather(*(one(n) for n in notifiers), return_exceptions=True)
    out: list[NotificationResult] = []
    for n, r in zip(notifiers, raw):
        name = getattr(n, "name", type(n).__name__)
        if isinstance(r, Exception):
            log.error("notification.%s erro inesperado: %s", name, redact(str(r)))
            out.append(NotificationResult(name, ok=False, error=type(r).__name__))
        else:
            _log_result(r)
            out.append(r)
    return out


def _log_result(r: NotificationResult) -> None:
    if r.attempts == 0:
        return  # nada a enviar nesse canal (abaixo do nível) — silencioso
    if r.ok:
        log.info("notification.%s enviado status=%s tentativas=%d",
                 r.channel, r.status if r.status is not None else "-", r.attempts)
    else:
        log.error("notification.%s falhou status=%s tentativas=%d erro=%s",
                  r.channel, r.status if r.status is not None else "-", r.attempts,
                  redact(r.error or ""))


class NotificationManager:
    """Agrupa os canais e centraliza o despacho (dispatch/announce), cada um com
    a sua política de nível. Um canal lento/quebrado não afeta os outros."""

    def __init__(self, notifiers: list[Notifier]):
        self.notifiers = notifiers

    def __bool__(self) -> bool:
        return bool(self.notifiers)

    async def dispatch(self, target: str, events: list[Event]) -> list[NotificationResult]:
        return await send_all(self.notifiers, target, events)

    async def announce(self, msg: str) -> list[NotificationResult]:
        async def one(n: Notifier) -> NotificationResult:
            return await n.announce(msg)

        raw = await asyncio.gather(*(one(n) for n in self.notifiers), return_exceptions=True)
        out: list[NotificationResult] = []
        for n, r in zip(self.notifiers, raw):
            name = getattr(n, "name", type(n).__name__)
            if isinstance(r, Exception):
                log.debug("announce.%s falhou: %s", name, redact(str(r)))
                out.append(NotificationResult(name, ok=False, error=type(r).__name__))
            else:
                out.append(r)
        return out
