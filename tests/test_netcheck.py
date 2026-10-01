"""Sondas de rede do doctor (netcheck): TCP/53 e HTTPS de saída, com a E/S
de socket substituída (offline)."""

import asyncio
from types import SimpleNamespace

from padme import netcheck


def _cfg(rdap=True, subdomains=False, webhook=False):
    return SimpleNamespace(
        timeout=5.0,
        collectors=SimpleNamespace(rdap=rdap, subdomains=subdomains),
        webhook=SimpleNamespace(enabled=webhook),
    )


def test_dns_tcp_ok(monkeypatch):
    monkeypatch.setattr(netcheck, "_system_resolvers", lambda: ["8.8.8.8"])

    async def connect(host, port, timeout):
        assert (host, port) == ("8.8.8.8", 53)
        return True
    monkeypatch.setattr(netcheck, "_tcp_connect", connect)
    ok, detail = asyncio.run(netcheck.check_dns_tcp())
    assert ok is True and "OK" in detail


def test_dns_tcp_bloqueado(monkeypatch):
    monkeypatch.setattr(netcheck, "_system_resolvers", lambda: ["1.1.1.1"])

    async def connect(host, port, timeout):
        return False
    monkeypatch.setattr(netcheck, "_tcp_connect", connect)
    ok, detail = asyncio.run(netcheck.check_dns_tcp())
    assert ok is False and "bloqueado" in detail


def test_dns_tcp_sem_resolvedor(monkeypatch):
    monkeypatch.setattr(netcheck, "_system_resolvers", lambda: [])
    ok, detail = asyncio.run(netcheck.check_dns_tcp())
    assert ok is None and "nenhum resolvedor" in detail


def test_https_ok_e_bloqueado(monkeypatch):
    async def ok(host, port, timeout):
        return True
    monkeypatch.setattr(netcheck, "_tcp_connect", ok)
    assert asyncio.run(netcheck.check_https())[0] is True

    async def no(host, port, timeout):
        return False
    monkeypatch.setattr(netcheck, "_tcp_connect", no)
    blocked, detail = asyncio.run(netcheck.check_https())
    assert blocked is False and "bloqueado" in detail


def test_run_monta_linhas_com_marcadores(monkeypatch):
    monkeypatch.setattr(netcheck, "_system_resolvers", lambda: ["8.8.8.8"])

    async def connect(host, port, timeout):
        return port == 443   # 53 bloqueado, 443 ok
    monkeypatch.setattr(netcheck, "_tcp_connect", connect)
    lines = asyncio.run(netcheck.run(_cfg(rdap=True)))
    assert any(line.startswith("  ! ") and "TCP/53" in line for line in lines)
    assert any(line.startswith("  ok: ") and "HTTPS" in line for line in lines)


def test_run_sem_saida_https_so_checa_dns(monkeypatch):
    monkeypatch.setattr(netcheck, "_system_resolvers", lambda: ["8.8.8.8"])

    async def connect(host, port, timeout):
        assert port == 53   # HTTPS não deve ser sondado
        return True
    monkeypatch.setattr(netcheck, "_tcp_connect", connect)
    lines = asyncio.run(netcheck.run(_cfg(rdap=False, subdomains=False, webhook=False)))
    assert len(lines) == 1 and "TCP/53" in lines[0]
