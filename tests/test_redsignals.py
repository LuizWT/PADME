"""Sinais RED adicionais: security headers, tech fingerprint e favicon hash.

Cada sinal é testado no comportamento E na confiabilidade (não gerar falso
'removed' quando a coleta é inconclusiva).
"""

import asyncio

import httpx

from padme.collectors import favicon, http
from padme.models import Kind, scope_of


# ── security headers (postura) ───────────────────────────────────────────────
def test_security_posture_https_inclui_hsts_e_ausentes():
    headers = httpx.Headers({"content-security-policy": "default-src 'self'",
                             "x-frame-options": "DENY"})
    present, missing = http._security_posture(headers, "https")
    assert "csp" in present and "xfo" in present
    assert "hsts" in missing and "nosniff" in missing  # ausentes
    assert set(present) | set(missing) == {"hsts", "csp", "xfo", "nosniff", "refpol", "permpol"}


def test_security_posture_http_exclui_hsts():
    present, missing = http._security_posture(httpx.Headers({}), "http")
    assert "hsts" not in present and "hsts" not in missing  # não avaliado em http


def test_security_posture_header_vazio_conta_como_ausente():
    present, missing = http._security_posture(
        httpx.Headers({"x-frame-options": "   "}), "https")
    assert "xfo" in missing and "xfo" not in present


# ── tech fingerprint ─────────────────────────────────────────────────────────
def test_tech_fingerprint_por_server_e_header():
    assert http._tech_fingerprint(httpx.Headers({"server": "nginx/1.25"})) == ["nginx"]
    tech = http._tech_fingerprint(httpx.Headers({"server": "cloudflare", "cf-ray": "abc"}))
    assert tech == ["Cloudflare"]                       # sem duplicar
    assert http._tech_fingerprint(httpx.Headers({})) == []
    combo = http._tech_fingerprint(httpx.Headers({"server": "nginx", "x-powered-by": "PHP/8.2"}))
    assert "nginx" in combo and "PHP" in combo


def test_http_collect_emite_httpsec_e_tech():
    def handler(req):
        return httpx.Response(200, headers={"server": "nginx", "content-type": "text/html"},
                              content=b"<title>ok</title>")

    async def run(security):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await http.collect_host("x.com", c, security=security)

    cr = asyncio.run(run(True))
    httpsec = [r for r in cr.records if r.kind == Kind.HTTPSEC]
    https = [r for r in cr.records if r.kind == Kind.HTTP]
    assert httpsec and https
    assert httpsec[0].value.startswith("faltando:")     # nenhum header de segurança
    assert https[0].metadata["tech"] == ["nginx"]
    # security=False não emite HTTPSEC
    cr2 = asyncio.run(run(False))
    assert not [r for r in cr2.records if r.kind == Kind.HTTPSEC]


def test_http_redirect_nao_gera_httpsec():
    def handler(req):
        return httpx.Response(301, headers={"location": "https://x.com/novo"})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await http.collect_host("x.com", c)

    cr = asyncio.run(run())
    assert not [r for r in cr.records if r.kind == Kind.HTTPSEC]  # 3xx: postura não avaliada


# ── favicon hash ─────────────────────────────────────────────────────────────
def test_favicon_200_gera_hash_estavel():
    def handler(req):
        return httpx.Response(200, content=b"\x00ICONDATA\x01")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await favicon.collect_host("x.com", c)

    cr = asyncio.run(run())
    assert cr.ok is True and len(cr.records) == 1
    r = cr.records[0]
    assert r.kind == Kind.FAVICON and r.key == "x.com"
    assert len(r.value) == 16 and r.metadata["algo"] == "sha256/16"


def test_favicon_404_ausencia_autoritativa():
    def handler(req):
        return httpx.Response(404, content=b"nope")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await favicon.collect_host("x.com", c)

    cr = asyncio.run(run())
    assert cr.ok is True and cr.records == []   # respondeu -> ausência real (permite REMOVED)


def test_favicon_timeout_preserva():
    def handler(req):
        raise httpx.ConnectTimeout("timeout")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await favicon.collect_host("x.com", c)

    cr = asyncio.run(run())
    assert cr.ok is False and cr.records == []  # inconclusivo -> preserva (sem falso removed)


# ── escopo: novos kinds mapeiam pro escopo certo (sem falso REMOVED) ─────────
def test_scope_of_httpsec_e_favicon():
    # HTTPSEC compartilha o escopo do HTTP (mesma resposta observada)
    assert scope_of(Kind.HTTPSEC, "https://a.com", "a.com") == ("http", "a.com")
    # FAVICON tem escopo próprio, por host
    assert scope_of(Kind.FAVICON, "a.com", "a.com") == ("favicon", "a.com")
