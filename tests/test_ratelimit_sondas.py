"""Rate-limit cobre toda sondagem ativa, não só HTTP (ponto 2 da revisão).

Antes, o pacing era um hook do httpx: connects de porta, handshakes TLS e o
bruteforce passavam sem freio, e o scan de portas abria a lista inteira de
todos os hosts de uma vez."""

import asyncio
import os
import tempfile

import pytest

from padme.collectors import bruteforce, ports, tls
from padme.config import CollectorsConfig, Config, NetworkConfig, _validate
from padme.engine import Engine
from padme.storage import Storage


def test_ports_respeita_teto_de_connects_simultaneos(monkeypatch):
    ativos = {"agora": 0, "pico": 0}

    async def fake_check(host, port, timeout, grab):
        ativos["agora"] += 1
        ativos["pico"] = max(ativos["pico"], ativos["agora"])
        await asyncio.sleep(0.01)
        ativos["agora"] -= 1
        return "closed", ""

    monkeypatch.setattr(ports, "_check_port", fake_check)

    async def run(limit):
        return await ports.collect_host("a.com", list(range(1, 21)), 5, limit=limit)

    asyncio.run(run(asyncio.Semaphore(3)))
    assert ativos["pico"] == 3
    ativos["pico"] = 0
    asyncio.run(run(None))                      # sem teto: a lista inteira de uma vez
    assert ativos["pico"] == 20


def test_ports_chama_o_pace_a_cada_connect(monkeypatch):
    async def fake_check(host, port, timeout, grab):
        return "closed", ""

    monkeypatch.setattr(ports, "_check_port", fake_check)
    chamadas: list[str] = []

    async def pace(host):
        chamadas.append(host)

    asyncio.run(ports.collect_host("a.com", [22, 80, 443], 5, pace=pace))
    assert chamadas == ["a.com"] * 3


def test_tls_chama_o_pace_antes_do_handshake(monkeypatch):
    monkeypatch.setattr(tls, "_blocking_cert", lambda host, port, timeout: None)
    chamadas: list[str] = []

    async def pace(host):
        chamadas.append(host)

    asyncio.run(tls.collect_host("a.com", 5, pace=pace))
    assert chamadas == ["a.com"]


def test_bruteforce_chama_o_pace_por_candidato(monkeypatch):
    async def fake_resolve(resolver, host):
        return set()

    monkeypatch.setattr(bruteforce, "_resolve_ips", fake_resolve)
    chamadas: list[str] = []

    async def pace(host):
        chamadas.append(host)

    asyncio.run(bruteforce.collect("a.com", ["www", "api", "dev"], 5, pace=pace))
    assert sorted(chamadas) == ["api.a.com", "dev.a.com", "www.a.com"]


def test_engine_liga_pace_e_teto_no_scan_de_portas(monkeypatch):
    recebido = {}

    async def fake_ports(host, plist, timeout, banner=True, pace=None, limit=None):
        recebido.update(pace=pace, limit=limit)
        from padme.models import CollectionResult
        return CollectionResult([], ok=True)

    monkeypatch.setattr(ports, "collect_host", fake_ports)
    db = tempfile.mktemp(suffix=".db")
    cfg = Config(targets=["a.com"], db_path=db, scope_confirmed=True,
                 network=NetworkConfig(allow_private_ips=True, rate_limit_rps=50,
                                       max_parallel_connects=7),
                 collectors=CollectorsConfig(
                     subdomains=False, bruteforce=False, wildcard=False, dns=False,
                     dns_records=False, http=False, favicon=False, tls=False,
                     takeover=False, ports=True))
    s = Storage(db)
    try:
        eng = Engine(cfg, s)
        asyncio.run(eng.scan_target("a.com"))
        assert recebido["pace"] == eng._rate.acquire
        assert isinstance(recebido["limit"], asyncio.Semaphore)
        assert recebido["limit"]._value == 7
    finally:
        s.close()
        os.remove(db)


def test_config_valida_teto_de_connects():
    cfg = Config(targets=["a.com"], network=NetworkConfig(max_parallel_connects=0))
    with pytest.raises(ValueError, match="max_parallel_connects"):
        _validate(cfg)
    assert NetworkConfig().max_parallel_connects == 256
