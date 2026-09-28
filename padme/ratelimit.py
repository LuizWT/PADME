"""Comportamento responsável: pacing das requisições ativas (§12 do roadmap).

A Padmé monitora superfície EXTERNA de alvos autorizados. Mesmo autorizado, um
monitor 24/7 não deve martelar o alvo: rajadas sujam o alerta do outro lado,
disparam WAF/rate-limit (429/503) e tornam a coleta imprevisível.

`RateLimiter` aplica dois freios, ambos in-process (sem fila/broker externo):

- **teto global** de requisições/segundo (`rps`), com **jitter** — o
  espaçamento entre requisições fica previsível e levemente aleatório, evitando
  batidas sincronizadas;
- **intervalo mínimo por host** (`per_host_interval`) — não concentra requisições
  seguidas no mesmo destino (vários collectors podem tocar o mesmo host num scan).

Ambos desligam sozinhos quando o valor é `<= 0` (no-op, sem espera). Nada aqui
aumenta a agressividade: os limites só tornam o scan igual ou mais educado.
É `asyncio`-safe: a reserva do próximo horário é serializada por lock.
"""

from __future__ import annotations

import asyncio
import random

import httpx

# Status transitórios que merecem uma nova tentativa (o alvo pediu pra esperar,
# ou é um erro de servidor efêmero). 4xx permanente (404/401/403) nunca repete.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_BACKOFF_CAP = 8.0


def _retry_after(resp: httpx.Response) -> float | None:
    """Segundos do header Retry-After (só a forma numérica; a data HTTP é
    ignorada — o backoff exponencial cobre esse caso)."""
    val = resp.headers.get("retry-after")
    if not val:
        return None
    try:
        return max(0.0, float(val.strip()))
    except ValueError:
        return None


def _backoff(attempt: int, base: float, retry_after: float | None) -> float:
    """Backoff exponencial com teto + jitter; respeita Retry-After se maior."""
    exp = min(_BACKOFF_CAP, base * (2 ** (attempt - 1))) + random.uniform(0, base / 2)
    return max(exp, retry_after) if retry_after is not None else exp


class RetryTransport(httpx.AsyncBaseTransport):
    """Wrapper de transporte httpx: repete em 429/5xx transitório e em erro de
    conexão/timeout, com backoff exponencial + jitter e respeito ao Retry-After.

    Torna o monitor educado com o alvo (recua quando pedem) e resiliente a
    hiccups de rede, sem repetir 4xx permanente. `max_retries=0` desliga."""

    def __init__(self, inner: httpx.AsyncBaseTransport, max_retries: int = 2,
                 backoff_base: float = 0.5):
        self._inner = inner
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = backoff_base

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        while True:
            try:
                resp = await self._inner.handle_async_request(request)
            except httpx.TransportError:
                if attempt >= self.max_retries:
                    raise
                attempt += 1
                await asyncio.sleep(_backoff(attempt, self.backoff_base, None))
                continue
            if resp.status_code not in _RETRY_STATUSES or attempt >= self.max_retries:
                return resp
            wait = _backoff(attempt + 1, self.backoff_base, _retry_after(resp))
            await resp.aclose()  # descarta o corpo antes de repetir
            attempt += 1
            await asyncio.sleep(wait)

    async def aclose(self) -> None:
        await self._inner.aclose()


class RateLimiter:
    def __init__(self, rps: float = 0.0, jitter_ms: int = 0,
                 per_host_interval: float = 0.0):
        self.rps = max(0.0, float(rps))
        self.jitter = max(0, int(jitter_ms)) / 1000.0
        self.per_host_interval = max(0.0, float(per_host_interval))
        self._interval = 1.0 / self.rps if self.rps > 0 else 0.0
        self._next = 0.0                      # próximo horário global permitido
        self._host_next: dict[str, float] = {}  # próximo horário por host
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._interval > 0.0 or self.per_host_interval > 0.0

    def _jitter(self) -> float:
        return random.uniform(0.0, self.jitter) if self.jitter else 0.0

    async def acquire(self, host: str | None = None) -> None:
        """Espera até o slot permitido (global e do host) e reserva o próximo."""
        if not self.enabled:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            allowed = now
            if self._interval > 0.0:
                allowed = max(allowed, self._next)
            if host is not None and self.per_host_interval > 0.0:
                allowed = max(allowed, self._host_next.get(host, 0.0))

            wait = allowed - now
            if self._interval > 0.0:
                self._next = allowed + self._interval + self._jitter()
            if host is not None and self.per_host_interval > 0.0:
                self._host_next[host] = allowed + self.per_host_interval
        if wait > 0:
            await asyncio.sleep(wait)


def from_config(cfg) -> RateLimiter:
    """Monta o RateLimiter a partir de cfg.network (valores 0 = desligado)."""
    net = cfg.network
    return RateLimiter(
        rps=getattr(net, "rate_limit_rps", 0.0),
        jitter_ms=getattr(net, "jitter_ms", 0),
        per_host_interval=getattr(net, "per_host_interval_ms", 0) / 1000.0,
    )
