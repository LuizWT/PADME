"""Disponibilidade de domínio registrável: PSL, parsing RDAP e a combinação
DNS+RDAP (check_registrable) que o takeover e o SPF órfão compartilham."""

import asyncio

from padme import domains
from padme.domains import (
    Availability,
    DomainCheck,
    check_registrable,
    is_claimable,
    rdap_availability,
    rdap_base_for,
    registrable_domain,
)


# ── PSL ──────────────────────────────────────────────────────────────────────
def test_registrable_domain():
    assert registrable_domain("a.b.exemplo.com.") == "exemplo.com"
    assert registrable_domain("x.site.co.uk") == "site.co.uk"
    assert registrable_domain("app.herokuapp.com") == "herokuapp.com"   # sufixo privado
    for interno in ("svc.corp.local", "api.internal", "x.test", "co.uk", ""):
        assert registrable_domain(interno) is None


# ── RDAP (parsing puro) ───────────────────────────────────────────────────────
def test_rdap_base_for():
    services = [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["org"], ["http://rdap.org/", "https://rdap.publicinterestregistry.org/rdap/"]]]
    assert rdap_base_for("com", services) == "https://rdap.verisign.com/com/v1/"
    assert rdap_base_for("NET", services) == "https://rdap.verisign.com/com/v1/"
    # prefere https e garante a barra final
    assert rdap_base_for("org", services) == "https://rdap.publicinterestregistry.org/rdap/"
    assert rdap_base_for("xyz", services) is None


def test_rdap_availability():
    assert rdap_availability(404, None) == Availability.FREE
    assert rdap_availability(200, {"status": ["active"]}) == Availability.REGISTERED
    assert rdap_availability(200, {}) == Availability.REGISTERED
    assert rdap_availability(200, {"status": ["client hold"]}) == Availability.PENDING_RELEASE
    assert rdap_availability(200, {"status": ["pending delete"]}) == Availability.PENDING_RELEASE
    assert rdap_availability(200, {"status": ["redemptionPeriod"]}) == Availability.PENDING_RELEASE
    assert rdap_availability(429, None) == Availability.UNKNOWN
    assert rdap_availability(500, None) == Availability.UNKNOWN


def test_is_claimable():
    assert is_claimable(Availability.FREE)
    assert is_claimable(Availability.PENDING_RELEASE)
    assert is_claimable(Availability.OUT_OF_ZONE)
    assert not is_claimable(Availability.REGISTERED)
    assert not is_claimable(Availability.UNKNOWN)


# ── combinação DNS + RDAP ─────────────────────────────────────────────────────
def _check(name, nx, rdap_av=None):
    async def ns(_d):
        return nx
    rdap = None
    if rdap_av is not None:
        async def rdap(_d):
            return rdap_av
    return asyncio.run(check_registrable(name, ns, rdap))


def test_check_tld_interno_nao_registravel():
    assert _check("svc.corp.local", True) == DomainCheck(None, Availability.REGISTERED)


def test_check_ns_inconclusivo_preserva():
    assert _check("x.alvo.com", None).availability == Availability.UNKNOWN


def test_check_zona_existe_sem_rdap_registrado():
    c = _check("sub.alvo.com", False)
    assert c == DomainCheck("alvo.com", Availability.REGISTERED)


def test_check_zona_existe_mas_rdap_ve_expiracao():
    # NS ainda responde, mas o registro já está em redemption -> pending
    c = _check("sub.alvo.com", False, Availability.PENDING_RELEASE)
    assert c.availability == Availability.PENDING_RELEASE


def test_check_fora_da_zona_sem_rdap_out_of_zone():
    c = _check("x.marca-antiga.net", True)
    assert c == DomainCheck("marca-antiga.net", Availability.OUT_OF_ZONE)


def test_check_fora_da_zona_rdap_confirma_livre():
    c = _check("x.marca-antiga.net", True, Availability.FREE)
    assert c == DomainCheck("marca-antiga.net", Availability.FREE)


def test_check_fora_da_zona_rdap_falha_mantem_sinal_dns():
    c = _check("x.marca-antiga.net", True, Availability.UNKNOWN)
    assert c.availability == Availability.OUT_OF_ZONE


def test_check_fora_da_zona_mas_rdap_diz_registrado():
    # delegação lame: o registro existe (atacante não pega) -> não reivindicável
    c = _check("x.marca-antiga.net", True, Availability.REGISTERED)
    assert not is_claimable(c.availability)


# ── cliente RDAP (resiliência, E/S injetada por MockTransport) ────────────────
def _rdap_with(handler):
    import httpx
    return domains.make_rdap(transport=httpx.MockTransport(handler))


def _bootstrap_body():
    return {"services": [[["com"], ["https://rdap.example/com/"]]]}


def test_make_rdap_fluxo_completo():
    import httpx

    def handler(req: httpx.Request) -> httpx.Response:
        if "data.iana.org" in str(req.url):
            return httpx.Response(200, json=_bootstrap_body())
        if str(req.url).endswith("/domain/livre.com"):
            return httpx.Response(404)
        if str(req.url).endswith("/domain/preso.com"):
            return httpx.Response(200, json={"status": ["pending delete"]})
        if str(req.url).endswith("/domain/ativo.com"):
            return httpx.Response(200, json={"status": ["active"]})
        return httpx.Response(500)

    rdap = _rdap_with(handler)
    assert asyncio.run(rdap("livre.com")) == Availability.FREE
    assert asyncio.run(rdap("preso.com")) == Availability.PENDING_RELEASE
    assert asyncio.run(rdap("ativo.com")) == Availability.REGISTERED


def test_make_rdap_tld_sem_servidor_vira_unknown():
    import httpx

    def handler(req):
        if "data.iana.org" in str(req.url):
            return httpx.Response(200, json=_bootstrap_body())
        raise AssertionError("não deveria consultar domínio sem base RDAP")

    assert asyncio.run(_rdap_with(handler)("algo.xyz")) == Availability.UNKNOWN


def test_make_rdap_rede_quebrada_vira_unknown():
    import httpx

    def handler(req):
        raise httpx.ConnectError("sem rede")

    assert asyncio.run(_rdap_with(handler)("qualquer.com")) == Availability.UNKNOWN
