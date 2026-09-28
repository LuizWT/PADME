"""Testes do pacing responsável (§12)."""

import asyncio
import time

import httpx

from padme.config import Config
from padme.ratelimit import RateLimiter, RetryTransport, from_config


def test_desligado_e_noop():
    rl = RateLimiter()  # tudo 0 -> desligado
    assert rl.enabled is False

    async def run():
        t0 = time.monotonic()
        for _ in range(50):
            await rl.acquire("x.com")
        return time.monotonic() - t0

    # sem limite, 50 acquires são praticamente instantâneos
    assert asyncio.run(run()) < 0.05


def test_teto_global_rps():
    # 20 rps -> intervalo de 50ms; 5 requisições gastam >= 4 intervalos (~200ms)
    rl = RateLimiter(rps=20)
    assert rl.enabled is True

    async def run():
        t0 = asyncio.get_running_loop().time()
        for _ in range(5):
            await rl.acquire()
        return asyncio.get_running_loop().time() - t0

    elapsed = asyncio.run(run())
    assert elapsed >= 0.18   # 4 * 50ms, com folga p/ variação de agendador
    assert elapsed < 0.6     # e não exagera


def test_intervalo_por_host_isola_hosts():
    # 100ms mínimo por host; dois hosts distintos NÃO esperam um pelo outro
    rl = RateLimiter(per_host_interval=0.1)
    assert rl.enabled is True

    async def run_pair():
        t0 = asyncio.get_running_loop().time()
        await rl.acquire("a.com")
        await rl.acquire("b.com")   # host diferente -> sem espera
        return asyncio.get_running_loop().time() - t0

    assert asyncio.run(run_pair()) < 0.05

    async def run_same():
        t0 = asyncio.get_running_loop().time()
        await rl.acquire("a.com")
        await rl.acquire("a.com")   # mesmo host -> espera ~100ms
        return asyncio.get_running_loop().time() - t0

    assert asyncio.run(run_same()) >= 0.09


def test_from_config_le_network():
    cfg = Config(targets=["x.com"])
    cfg.network.rate_limit_rps = 10
    cfg.network.per_host_interval_ms = 250
    rl = from_config(cfg)
    assert rl.enabled is True
    assert rl.rps == 10
    assert rl.per_host_interval == 0.25


def test_from_config_padrao_desligado():
    rl = from_config(Config(targets=["x.com"]))
    assert rl.enabled is False


# ── RetryTransport ───────────────────────────────────────────────────────────
def _client_with(handler, **kw):
    inner = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=RetryTransport(inner, backoff_base=0.001, **kw))


def test_retry_repete_em_503_e_sucede():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] >= 3 else 503)

    async def run():
        async with _client_with(handler, max_retries=3) as c:
            return await c.get("https://a.example/")

    resp = asyncio.run(run())
    assert resp.status_code == 200
    assert calls["n"] == 3          # 2 falhas + 1 sucesso


def test_retry_respeita_teto():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(503)

    async def run():
        async with _client_with(handler, max_retries=2) as c:
            return await c.get("https://a.example/")

    resp = asyncio.run(run())
    assert resp.status_code == 503
    assert calls["n"] == 3          # tentativa inicial + 2 retries


def test_nao_repete_4xx_permanente():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(404)

    async def run():
        async with _client_with(handler, max_retries=3) as c:
            return await c.get("https://a.example/")

    resp = asyncio.run(run())
    assert resp.status_code == 404
    assert calls["n"] == 1          # 404 não é transitório


def test_max_retries_zero_desliga():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(503)

    async def run():
        async with _client_with(handler, max_retries=0) as c:
            return await c.get("https://a.example/")

    asyncio.run(run())
    assert calls["n"] == 1


def test_retry_em_erro_de_conexao():
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] < 2:
            raise httpx.ConnectError("boom", request=req)
        return httpx.Response(200)

    async def run():
        async with _client_with(handler, max_retries=2) as c:
            return await c.get("https://a.example/")

    resp = asyncio.run(run())
    assert resp.status_code == 200 and calls["n"] == 2
