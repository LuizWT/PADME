"""Anti-SSRF com follow_redirects ligado e faixas não-públicas (itens 9 e 10).

Antes, `follow_redirects: true` delegava ao httpx, que seguia qualquer Location
(inclusive para 127.0.0.1), e 100.64.0.0/10 (CGNAT) passava como IP público."""

import asyncio

import httpx

from padme import netpolicy
from padme.collectors import favicon, http
from padme.netpolicy import is_public_ip, redirect_target_allowed


# ── item 10: o que conta como IP público ────────────────────────────────────
def test_cgnat_e_faixas_especiais_nao_sao_publicas():
    for ip in ("100.64.0.1", "100.127.255.254",   # CGNAT / Tailscale
               "192.0.2.10", "198.18.0.1",        # documentação / benchmark
               "224.0.0.1", "255.255.255.255"):   # multicast / broadcast
        assert not is_public_ip(ip), ip
    assert is_public_ip("8.8.8.8")


def test_ipv4_embutido_em_ipv6_e_avaliado_por_dentro():
    assert not is_public_ip("::ffff:10.0.0.1")        # IPv4 mapeado
    assert not is_public_ip("2002:0a00:0001::1")      # 6to4 de 10.0.0.1
    assert not is_public_ip("64:ff9b::a00:1")         # NAT64 de 10.0.0.1
    assert is_public_ip("64:ff9b::808:808")           # NAT64 de 8.8.8.8


# ── item 9: validação de cada salto de redirect ─────────────────────────────
def _allowed(url, allow_private=False):
    return asyncio.run(redirect_target_allowed(url, allow_private, timeout=1))


def test_salto_ip_literal_e_esquema():
    assert not _allowed("http://127.0.0.1/admin")
    assert not _allowed("http://100.64.1.1/")
    assert _allowed("https://8.8.8.8/")
    assert not _allowed("ftp://8.8.8.8/")           # só http/https
    assert not _allowed("file:///etc/passwd")
    assert _allowed("http://127.0.0.1/", allow_private=True)   # opt-in consciente


def test_salto_por_nome_resolve_antes(monkeypatch):
    table = {"interno.alvo.com": {"10.1.2.3"}, "misto.alvo.com": {"8.8.8.8", "10.0.0.1"},
             "publico.alvo.com": {"8.8.8.8"}}

    async def fake_resolve(host, timeout):
        return table.get(host, set())

    monkeypatch.setattr(netpolicy, "_resolve_host", fake_resolve)
    assert not _allowed("http://interno.alvo.com/")
    assert not _allowed("http://misto.alvo.com/")     # basta um IP interno
    assert not _allowed("http://nao-resolve.alvo.com/")  # na dúvida, não segue
    assert _allowed("http://publico.alvo.com/")


def _client(routes: dict[str, httpx.Response], seen: list[str]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return routes.get(str(request.url), httpx.Response(404))
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _collect_http(routes, seen, follow=True):
    async with _client(routes, seen) as c:
        return await http.collect_host("a.com", c, follow_redirects=follow, security=False)


def test_http_nao_segue_redirect_para_rede_interna():
    seen: list[str] = []
    routes = {"https://a.com": httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})}
    cr = asyncio.run(_collect_http(routes, seen))
    assert not any("127.0.0.1" in u for u in seen)          # nunca requisitou o interno
    rec = next(r for r in cr.records if r.key == "https://a.com")
    assert rec.metadata["status"] == 302 and rec.metadata["location"] == "http://127.0.0.1/admin"


def test_http_segue_redirect_publico_validado():
    seen: list[str] = []
    routes = {
        "https://a.com": httpx.Response(301, headers={"location": "https://8.8.8.8/"}),
        "https://8.8.8.8/": httpx.Response(200, headers={"content-type": "text/html"},
                                           text="<title>destino</title>"),
    }
    cr = asyncio.run(_collect_http(routes, seen))
    rec = next(r for r in cr.records if r.key == "https://a.com")
    assert rec.metadata["status"] == 200 and rec.metadata["title"] == "destino"


def test_http_respeita_teto_de_saltos():
    seen: list[str] = []
    routes = {f"https://8.8.8.{i}/": httpx.Response(302, headers={"location": f"https://8.8.8.{i + 1}/"})
              for i in range(10)}
    routes["https://a.com"] = httpx.Response(302, headers={"location": "https://8.8.8.0/"})
    asyncio.run(_collect_http(routes, seen))
    https_hops = [u for u in seen if u.startswith("https://")]
    assert len(https_hops) == 1 + http.MAX_REDIRECTS         # origem + teto


def test_follow_desligado_nao_segue_nem_publico():
    seen: list[str] = []
    routes = {"https://a.com": httpx.Response(301, headers={"location": "https://8.8.8.8/"})}
    asyncio.run(_collect_http(routes, seen, follow=False))
    assert "https://8.8.8.8/" not in seen


def test_favicon_nao_segue_redirect_para_rede_interna():
    seen: list[str] = []
    routes = {"https://a.com/favicon.ico":
              httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})}

    async def run():
        async with _client(routes, seen) as c:
            return await favicon.collect_host("a.com", c, follow_redirects=True)

    cr = asyncio.run(run())
    assert not any("169.254.169.254" in u for u in seen)   # metadata da cloud: bloqueado
    assert cr.records == []
