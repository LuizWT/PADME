"""Detecção: dangling CNAME genérico, base de takeover como dado, postura de
e-mail fraca (SPF/DMARC) e TLS nas portas de TLS implícito."""

import asyncio
import json
import ssl
from importlib import resources
from types import SimpleNamespace

from padme import risk as L
from padme.collectors import takeover, tls
from padme.engine import Engine
from padme.mailpolicy import dmarc_tag, spf_all_qualifier, weaknesses
from padme.models import CollectionResult, Event, EventType, Kind, Record, ScanResult
from padme.panel_metrics import _collect_problems
from padme.risk import Confidence, Level, assess


# ── base de fingerprints como dado do pacote ────────────────────────────────
def test_fingerprints_vem_do_json_empacotado():
    doc = json.loads(resources.files("padme").joinpath(
        "data/takeover_fingerprints.json").read_text("utf-8"))
    assert doc["reviewed"] and doc["services"]
    assert takeover.FINGERPRINTS == doc["services"]
    assert takeover.FINGERPRINTS_REVIEWED == doc["reviewed"]
    assert takeover.match_service("x.github.io")["service"] == "GitHub Pages"


# ── dangling CNAME genérico ─────────────────────────────────────────────────
def test_registrable_domain():
    assert takeover.registrable_domain("a.b.exemplo.com.") == "exemplo.com"
    assert takeover.registrable_domain("cdn.loja.com.br") == "loja.com.br"
    assert takeover.registrable_domain("x.site.co.uk") == "site.co.uk"


def _dangling(monkeypatch, resolves, free, cname_ok=True):
    async def fake_cname(h, t):
        return "cdn.marca-antiga.net", resolves, cname_ok

    async def fake_free(domain, timeout):
        assert domain == "marca-antiga.net"
        return free

    monkeypatch.setattr(takeover, "_cname_target", fake_cname)
    monkeypatch.setattr(takeover, "_domain_unregistered", fake_free)
    return asyncio.run(takeover.collect_host("static.alvo.com", client=None, timeout=5))


def test_cname_para_dominio_nao_registrado_vira_takeover(monkeypatch):
    cr = _dangling(monkeypatch, resolves=False, free=True)
    assert cr.ok and len(cr.records) == 1
    r = cr.records[0]
    assert r.kind == Kind.TAKEOVER and r.metadata["domain"] == "marca-antiga.net"
    ev = Event("alvo.com", EventType.ADDED, Kind.TAKEOVER, r.key, new_value=r.value,
               metadata=r.metadata)
    a = assess(ev)
    assert a.level == Level.CRITICAL and a.confidence == Confidence.HIGH


def test_cname_nxdomain_em_dominio_existente_nao_e_achado(monkeypatch):
    cr = _dangling(monkeypatch, resolves=False, free=False)
    assert cr.ok and cr.records == []


def test_cname_dominio_inconclusivo_preserva(monkeypatch):
    cr = _dangling(monkeypatch, resolves=False, free=None)
    assert not cr.ok and cr.records == []


def test_cname_que_resolve_nao_consulta_registro(monkeypatch):
    cr = _dangling(monkeypatch, resolves=True, free=True)
    assert cr.ok and cr.records == []


# ── postura de e-mail ───────────────────────────────────────────────────────
def test_spf_qualificador_all():
    assert spf_all_qualifier("v=spf1 include:_spf.google.com -all") == "-"
    assert spf_all_qualifier("v=spf1 a mx all") == "+"
    assert spf_all_qualifier("v=spf1 +all") == "+"
    assert spf_all_qualifier("v=spf1 ?all") == "?"
    assert spf_all_qualifier("v=spf1 include:x.com") == ""
    assert dmarc_tag("v=DMARC1; p=reject; sp=none", "sp") == "none"


def _mail(key, value, etype=EventType.ADDED):
    return Event("x.com", etype, Kind.MAILSEC, key, new_value=value)


def test_spf_permissivo_eleva_high():
    a = assess(_mail("x.com|SPF", "v=spf1 +all"))
    assert a.level == Level.HIGH and L.SPF_PERMISSIVE in a.reasons
    ok = assess(_mail("x.com|SPF", "v=spf1 mx -all"))
    assert L.SPF_PERMISSIVE not in ok.reasons and ok.level == ok.base


def test_dmarc_sp_none_eleva_high():
    a = assess(_mail("x.com|DMARC", "v=DMARC1; p=reject; sp=none"))
    assert a.level == Level.HIGH and L.DMARC_SUBDOMAINS_NOT_ENFORCED in a.reasons
    # p=none já cobre: não duplica a razão de subdomínio
    b = assess(_mail("x.com|DMARC", "v=DMARC1; p=none; sp=none"))
    assert b.reasons == [L.DMARC_NOT_ENFORCED]


def test_painel_lista_postura_fraca():
    by_target = {"x.com": {"mailsec": [
        {"key": "x.com|SPF", "value": "v=spf1 ?all", "metadata": {"type": "spf"}},
        {"key": "x.com|DMARC", "value": "v=DMARC1; p=reject", "metadata": {"type": "dmarc"}},
    ]}}
    probs = _collect_problems(by_target, {})
    assert [p["kind"] for p in probs] == ["E-MAIL"]
    assert "?all" in probs[0]["det"]
    assert weaknesses("dmarc", "v=DMARC1; p=quarantine") == []


# ── TLS nas portas de TLS implícito ─────────────────────────────────────────
def _engine_stub():
    async def pace(host):
        return None
    cfg = SimpleNamespace(timeout=5, collectors=SimpleNamespace(cert_expiry_days=14))
    return SimpleNamespace(cfg=cfg, _rate=SimpleNamespace(acquire=pace))


def _port(p):
    return Record(Kind.PORT, f"h.com:{p}", "open", metadata={"port": p})


def test_tls_sondado_nas_portas_abertas_de_tls_implicito(monkeypatch):
    sondadas = []

    async def fake_tls(host, timeout, port=443, cert_expiry_days=14, pace=None,
                       handshake_fail_ok=False):
        sondadas.append((port, handshake_fail_ok))
        return CollectionResult(records=[Record(Kind.TLS, f"{host}:{port}", "cert")])

    monkeypatch.setattr(tls, "collect_host", fake_tls)
    base = CollectionResult(records=[Record(Kind.TLS, "h.com:443", "cert")])
    ports_cr = CollectionResult(records=[_port(22), _port(443), _port(8443), _port(993)])
    out = asyncio.run(Engine._tls_extra_ports(_engine_stub(), "h.com", base, ports_cr,
                                              ScanResult("h.com")))
    assert sondadas == [(993, True), (8443, True)]
    assert {r.key for r in out.records} == {"h.com:443", "h.com:993", "h.com:8443"}
    assert out.ok


def test_tls_escopo_nao_autoritativo_com_port_scan_inconclusivo(monkeypatch):
    base = CollectionResult(records=[Record(Kind.TLS, "h.com:443", "cert")])
    out = asyncio.run(Engine._tls_extra_ports(_engine_stub(), "h.com", base,
                                              CollectionResult(ok=False), ScanResult("h.com")))
    assert not out.ok and len(out.records) == 1


def test_porta_extra_sem_tls_e_observacao_definitiva(monkeypatch):
    def boom(host, port, timeout):
        raise ssl.SSLError("wrong version number")

    monkeypatch.setattr(tls, "_blocking_cert", boom)
    extra = asyncio.run(tls.collect_host("h.com", 5, port=8443, handshake_fail_ok=True))
    assert extra.ok and extra.records == []
    main = asyncio.run(tls.collect_host("h.com", 5))
    assert not main.ok  # na 443 continua preservando


def test_doctor_avisa_base_de_takeover_desatualizada(monkeypatch):
    from padme import cli
    monkeypatch.setattr(takeover, "FINGERPRINTS_REVIEWED", "2020-01-01")
    assert cli._fingerprints_stale_days() > 180
    monkeypatch.setattr(takeover, "FINGERPRINTS_REVIEWED", "2999-01-01")
    assert cli._fingerprints_stale_days() == 0
