"""P0.5 — cada collector distingue observação autoritativa (ok) de falha."""

import asyncio

import httpx

from padme.collectors import http, ports, subdomains, tls


# ── HTTP: não segue redirect + ok ───────────────────────────────────────────
def test_http_nao_segue_redirect_registra_location():
    def handler(req):
        return httpx.Response(302, headers={"location": "http://127.0.0.1/interno"})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await http.collect_host("x.com", c)  # follow_redirects=False default

    cr = asyncio.run(run())
    assert cr.ok is True
    assert any("302" in r.value and "127.0.0.1" in r.value for r in cr.records)


def test_http_ambos_esquemes_falham_preserva():
    def handler(req):
        raise httpx.ConnectError("sem rota")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await http.collect_host("x.com", c)

    cr = asyncio.run(run())
    assert cr.ok is False and cr.records == []


# ── PORTS: só-timeout preserva; recusada é definitiva ───────────────────────
def test_ports_todos_timeout_preserva(monkeypatch):
    async def fake(host, port, timeout, grab):
        return "unknown", ""

    monkeypatch.setattr(ports, "_check_port", fake)
    cr = asyncio.run(ports.collect_host("x.com", [22, 80], 5))
    assert cr.ok is False and cr.records == []


def test_ports_recusada_e_aberta_sao_definitivas(monkeypatch):
    async def fake(host, port, timeout, grab):
        return ("open", "") if port == 80 else ("closed", "")

    monkeypatch.setattr(ports, "_check_port", fake)
    cr = asyncio.run(ports.collect_host("x.com", [22, 80], 5))
    assert cr.ok is True
    assert [r.key for r in cr.records] == ["x.com:80"]


def test_ports_banner_entra_no_valor(monkeypatch):
    async def fake(host, port, timeout, grab):
        return ("open", "SSH-2.0-OpenSSH_8.9") if port == 22 else ("closed", "")

    monkeypatch.setattr(ports, "_check_port", fake)
    cr = asyncio.run(ports.collect_host("x.com", [22, 443], 5))
    r = cr.records[0]
    assert r.key == "x.com:22"
    assert "SSH-2.0-OpenSSH_8.9" in r.value and r.metadata["banner"] == "SSH-2.0-OpenSSH_8.9"


# ── TLS: timeout preserva; recusada é definitiva vazia ──────────────────────
def test_tls_timeout_preserva(monkeypatch):
    def boom(host, port, timeout):
        raise TimeoutError()

    monkeypatch.setattr(tls, "_blocking_cert", boom)
    cr = asyncio.run(tls.collect_host("x.com", 5))
    assert cr.ok is False


def test_tls_recusada_definitiva_vazia(monkeypatch):
    def boom(host, port, timeout):
        raise ConnectionRefusedError()

    monkeypatch.setattr(tls, "_blocking_cert", boom)
    cr = asyncio.run(tls.collect_host("x.com", 5))
    assert cr.ok is True and cr.records == []


# ── SUBDOMAINS: todas as fontes caindo != "todos removidos" ─────────────────
def test_subdomains_todas_fontes_falham_ok_false(monkeypatch):
    async def fake_fetch(client, url):
        return None, False   # nenhuma fonte respondeu

    monkeypatch.setattr(subdomains, "_fetch_json", fake_fetch)
    cr = asyncio.run(subdomains.collect("alvo.com", client=None))
    assert cr.ok is False
    assert "alvo.com" in cr.hosts   # apex ainda entra pra inspeção


def test_subdomains_uma_fonte_ok(monkeypatch):
    async def fake_fetch(client, url):
        return ["api.alvo.com", "www.alvo.com"], True

    monkeypatch.setattr(subdomains, "_fetch_json", fake_fetch)
    cr = asyncio.run(subdomains.collect("alvo.com", client=None))
    assert cr.ok is True
    assert {"api.alvo.com", "www.alvo.com"} <= cr.hosts
