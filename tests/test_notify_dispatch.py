"""P0.2 / P0.8 / P0.11 + §14 — severidade por canal, retry, isolamento e chunking."""

import asyncio

import httpx

from padme.levels import Level
from padme.models import Event, EventType, Kind
from padme.notify import NotificationResult, chunk_text, send_all
from padme.notify.base import post_with_retry


# ── chunk_text robusto (§14 / cenário 8) ────────────────────────────────────
def test_chunk_curto():
    assert chunk_text("oi", 10) == ["oi"]


def test_chunk_exato_no_limite():
    assert chunk_text("x" * 10, 10) == ["x" * 10]


def test_chunk_vazio():
    assert chunk_text("", 10) == []


def test_chunk_linha_gigante():
    big = "x" * 25
    out = chunk_text(big, 10)
    assert all(len(c) <= 10 for c in out)     # nunca ultrapassa o limite
    assert all(c for c in out)                # nenhum chunk vazio
    assert "".join(out) == big                # não perde conteúdo


def test_chunk_multilinhas():
    out = chunk_text("aaa\nbbb\nccc\nddd", 5)
    assert all(len(c) <= 5 for c in out)
    assert all(c for c in out)


# ── post_with_retry ─────────────────────────────────────────────────────────
def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_retry_em_429_e_sucesso():
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        if n["c"] < 3:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(204)

    async def run():
        async with _client(handler) as c:
            return await post_with_retry(c, "https://x/hook", "discord", json={"a": 1})

    res = asyncio.run(run())
    assert res.ok and res.attempts == 3 and res.status == 204


def test_retry_em_5xx():
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(500) if n["c"] == 1 else httpx.Response(200)

    async def run():
        async with _client(handler) as c:
            return await post_with_retry(c, "https://x", "telegram", json={})

    res = asyncio.run(run())
    assert res.ok and res.attempts == 2


def test_sem_retry_em_401():
    n = {"c": 0}

    def handler(req):
        n["c"] += 1
        return httpx.Response(401)

    async def run():
        async with _client(handler) as c:
            return await post_with_retry(c, "https://x", "telegram", json={})

    res = asyncio.run(run())
    assert not res.ok and res.attempts == 1 and res.status == 401 and n["c"] == 1


def test_erro_nao_vaza_url_no_result():
    def handler(req):
        raise httpx.ConnectError("falhou conectando em https://api.telegram.org/botSECRETO/x")

    async def run():
        async with _client(handler) as c:
            return await post_with_retry(c, "https://x", "telegram", json={}, max_attempts=1)

    res = asyncio.run(run())
    assert not res.ok
    assert "SECRETO" not in (res.error or "")   # erro seguro, sem detalhe da URL


# ── send_all: severidade por canal + isolamento ─────────────────────────────
class _Fake:
    def __init__(self, name, level, ok=True, boom=False):
        self.name = name
        self.level = level
        self._ok = ok
        self._boom = boom
        self.received = None

    async def notify_events(self, target, events):
        if self._boom:
            raise RuntimeError("boom")
        self.received = list(events)
        return NotificationResult(self.name, ok=self._ok, attempts=1, status=204)


def _events():
    return [
        Event("x.com", EventType.ADDED, Kind.TAKEOVER, "a.x.com"),                 # CRITICAL
        Event("x.com", EventType.ADDED, Kind.PORT, "x.com:8080"),                  # HIGH
        Event("x.com", EventType.CHANGED, Kind.HTTP, "http://x.com", "404", "200"),  # MEDIUM
        Event("x.com", EventType.REMOVED, Kind.PORT, "x.com:22", "open", None),    # LOW
        Event("x.com", EventType.ADDED, Kind.DNS, "x.com|A|1.2.3.4", None, "1.2.3.4"),  # DEBUG
    ]


def test_severidade_por_canal():
    tg = _Fake("telegram", Level.MEDIUM)
    dc = _Fake("discord", Level.DEBUG)
    asyncio.run(send_all([tg, dc], "x.com", _events()))
    assert len(dc.received) == 5   # debug -> recebe tudo
    assert len(tg.received) == 3   # medium -> critical + high + medium


def test_falha_de_um_canal_nao_impede_outro():
    tg = _Fake("telegram", Level.DEBUG, ok=True)
    dc = _Fake("discord", Level.DEBUG, boom=True)
    results = asyncio.run(send_all([tg, dc], "x.com", _events()))
    by = {r.channel: r for r in results}
    assert by["telegram"].ok is True
    assert by["discord"].ok is False       # falha registrada
    assert tg.received is not None         # telegram enviou apesar do discord estourar


def test_canal_sem_eventos_no_nivel_nao_dispara():
    tg = _Fake("telegram", Level.CRITICAL)  # só takeover
    only_debug = [Event("x.com", EventType.ADDED, Kind.DNS, "x.com|A|1", None, "1")]
    results = asyncio.run(send_all([tg], "x.com", only_debug))
    assert results[0].ok and results[0].attempts == 0
    assert tg.received is None               # nem chamou notify_events
