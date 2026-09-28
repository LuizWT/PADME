"""Testes do pacing responsável (§12)."""

import asyncio
import time

from padme.config import Config
from padme.ratelimit import RateLimiter, from_config


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
