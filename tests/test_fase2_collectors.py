"""Fase 2 — correções dos collectors (§16/18/19/21/38/41/42/43)."""

import asyncio
import logging
import os
import tempfile

import dns.exception
import dns.resolver
import httpx
import pytest

from padme.collectors import bruteforce, http, subdomains, takeover, tls
from padme.collectors.wildcard import classify_probe_ips


# ── §38 apex não é subdomínio ───────────────────────────────────────────────
def test_apex_nao_vira_subdomain(monkeypatch):
    async def fake_fetch(client, url):
        return ["alvo.com", "api.alvo.com"], True

    monkeypatch.setattr(subdomains, "_fetch_json", fake_fetch)
    cr = asyncio.run(subdomains.collect("alvo.com", client=None))
    keys = {r.key for r in cr.records}
    assert "alvo.com" not in keys        # apex não é Record SUBDOMAIN
    assert "api.alvo.com" in keys
    assert "alvo.com" in cr.hosts        # mas continua sendo inspecionado


# ── §18 match de CNAME respeita fronteira de domínio ────────────────────────
def test_match_service_fronteira():
    assert takeover.match_service("foo.github.io")["service"] == "GitHub Pages"
    assert takeover.match_service("github.io")["service"] == "GitHub Pages"
    assert takeover.match_service("evilgithub.io") is None          # não é substring
    assert takeover.match_service("github.io.attacker.com") is None  # sufixo diferente


# ── §19 resolução considera A E AAAA ────────────────────────────────────────
class _FakeResolver:
    def __init__(self, behavior):
        self.behavior = behavior
        self.lifetime = 0.0

    async def resolve(self, name, rtype):
        b = self.behavior.get(rtype, "timeout")
        if b == "ok":
            return ["<answer>"]
        if b == "nx":
            raise dns.resolver.NXDOMAIN
        if b == "noanswer":
            raise dns.resolver.NoAnswer
        raise dns.exception.Timeout


def _resolves(behavior):
    return asyncio.run(takeover._resolves(_FakeResolver(behavior), "alvo.exemplo"))


def test_resolves_com_a():
    assert _resolves({"A": "ok"}) == "resolves"


def test_resolves_nxdomain_e_dangling():
    assert _resolves({"A": "nx"}) == "nxdomain"


def test_resolves_so_aaaa_nao_e_dangling():
    assert _resolves({"A": "noanswer", "AAAA": "ok"}) == "resolves"


def test_resolves_timeout_e_unknown():
    assert _resolves({"A": "timeout"}) == "unknown"


def test_resolves_existe_sem_endereco():
    assert _resolves({"A": "noanswer", "AAAA": "noanswer"}) == "resolves"


# ── §21 HTTP limita o corpo lido ────────────────────────────────────────────
def test_http_limita_corpo():
    big = b"<title>" + b"x" * 500_000 + b"</title>"

    def handler(req):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=big)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            cache: dict[str, str] = {}
            cr = await http.collect_host("x.com", c, cache=cache, max_bytes=1024)
            return cr, cache

    cr, cache = asyncio.run(run())
    assert cr.ok is True
    assert cache and all(len(v) <= 1024 for v in cache.values())  # corpo truncado


# ── §41/§42 validação de wordlist ───────────────────────────────────────────
def test_wordlist_configurada_inexistente_erra():
    with pytest.raises(FileNotFoundError):
        bruteforce.load_words("/caminho/que/nao/existe/wl.txt")


def test_wordlist_normaliza_e_dedup():
    p = tempfile.mktemp(suffix=".txt")
    open(p, "w").write("# comentário\nAPI\napi\n  dev  \n\nbad_label!\n*.wild\nok-1\n")
    words = bruteforce.load_words(p)
    os.remove(p)
    assert words == ["api", "dev", "ok-1"]  # minúsculo, dedup, trim, sem inválido/wildcard


# ── §43 wildcard expõe confiança (sem mudar supressão) ──────────────────────
def test_wildcard_confidence():
    wc = classify_probe_ips([{"1.2.3.4"}, {"1.2.3.4"}, set()])
    assert wc.active is True and wc.confidence == round(2 / 3, 2)
    vazio = classify_probe_ips([set(), set(), set()])
    assert vazio.active is False and vazio.confidence == 0.0


# ── §16 TLS: parsing parcial é observável (não engolido) ────────────────────
def test_tls_cert_parcial_loga(monkeypatch, caplog):
    def fake(host, port, timeout):
        return {"fp": "abc123", "issuer": "", "not_after": None}

    monkeypatch.setattr(tls, "_blocking_cert", fake)
    with caplog.at_level(logging.DEBUG, logger="padme"):
        cr = asyncio.run(tls.collect_host("x.com", 5))
    assert cr.ok is True
    assert any(r.kind.value == "tls" for r in cr.records)   # ainda emite o TLS
    assert any("cert parcial" in r.getMessage() for r in caplog.records)
