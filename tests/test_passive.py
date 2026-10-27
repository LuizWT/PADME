"""Fontes passivas de subdomínio: parsers, consulta (MockTransport), regra de
"só entra se resolve", intervalo entre consultas e integração com o engine."""

import asyncio
import json
import os
import tempfile

import httpx
import pytest

from padme.collectors import passive
from padme.collectors import subdomains as submod
from padme.collectors import wildcard as wcmod
from padme.config import CollectorsConfig, Config
from padme.engine import Engine
from padme.logredact import redact
from padme.models import CollectionResult
from padme.storage import Storage

APEX = "acme.com"


# ── parsers (formatos documentados de cada API) ─────────────────────────────
def test_parsers_por_fonte_e_filtro_do_apex():
    certspotter = json.dumps([{"dns_names": ["acme.com", "www.acme.com", "*.dev.acme.com"]},
                              {"dns_names": ["acme.com.evil.net", "notacme.com"]}])
    assert passive._parse("certspotter", certspotter, APEX) == {"acme.com", "www.acme.com", "dev.acme.com"}
    otx = json.dumps({"passive_dns": [{"hostname": "vpn.acme.com", "address": "1.2.3.4"},
                                      {"hostname": "x.other.org"}], "count": 2})
    assert passive._parse("otx", otx, APEX) == {"vpn.acme.com"}
    wayback = "http://old.acme.com/login\nhttps://shop.acme.com:8443/a?b=c\nhttp://acme.com/\n"
    assert passive._parse("wayback", wayback, APEX) == {"old.acme.com", "shop.acme.com", "acme.com"}
    assert passive._parse("hackertarget", "mail.acme.com,1.1.1.1\nftp.acme.com,2.2.2.2\n",
                          APEX) == {"mail.acme.com", "ftp.acme.com"}
    st = json.dumps({"subdomains": ["api", "staging.app", "", None], "endpoint": "/v1"})
    assert passive._parse("securitytrails", st, APEX) == {"api.acme.com", "staging.app.acme.com"}
    vt = json.dumps({"data": [{"id": "cdn.acme.com", "type": "domain"}], "links": {}})
    assert passive._parse("virustotal", vt, APEX) == {"cdn.acme.com"}


def test_hackertarget_cota_estourada_e_erro_nao_lista_vazia():
    with pytest.raises(ValueError):
        passive._parse("hackertarget", "API count exceeded - Increase Quota with Membership", APEX)
    with pytest.raises(ValueError):
        passive._parse("hackertarget", "error check your search parameter", APEX)


# ── consulta ─────────────────────────────────────────────────────────────────
def _transport(log):
    def handler(req: httpx.Request) -> httpx.Response:
        log.append((req.url.host, dict(req.headers)))
        host = req.url.host
        if host == "api.certspotter.com":
            return httpx.Response(200, json=[{"dns_names": ["a.acme.com"]}])
        if host == "otx.alienvault.com":
            return httpx.Response(503)                     # fonte fora do ar
        if host == "web.archive.org":
            return httpx.Response(200, text="http://b.acme.com/x\n")
        if host == "www.virustotal.com":
            page = req.url.params.get("cursor")
            if page is None:
                return httpx.Response(200, json={
                    "data": [{"id": "v1.acme.com"}],
                    "links": {"next": "https://www.virustotal.com/api/v3/domains/acme.com/subdomains?cursor=2"}})
            return httpx.Response(200, json={
                "data": [{"id": "v2.acme.com"}],
                "links": {"next": "https://evil.example/steal"}})   # nunca seguir para fora
        return httpx.Response(404)
    return httpx.MockTransport(handler)


@pytest.mark.passive_sources
def test_query_sources_status_chave_e_paginacao_segura():
    log = []
    names, status = asyncio.run(passive.query_sources(
        APEX, ["certspotter", "otx", "wayback", "virustotal", "securitytrails"],
        {"virustotal": "vt-secret"}, 5, transport=_transport(log)))
    assert names == {"a.acme.com", "b.acme.com", "v1.acme.com", "v2.acme.com"}
    assert status["certspotter"] == "1 nome(s)" and status["otx"].startswith("erro")
    assert status["securitytrails"] == "sem chave"          # sem chave: nem consulta
    hosts = [h for h, _ in log]
    assert "evil.example" not in hosts                       # paginação só dentro da API
    vt = [hd for h, hd in log if h == "www.virustotal.com"]
    assert len(vt) == 2 and all(hd.get("x-apikey") == "vt-secret" for hd in vt)
    assert all("x-apikey" not in hd for h, hd in log if h != "www.virustotal.com")


# ── coleta: só entra o que resolve ──────────────────────────────────────────
@pytest.mark.passive_sources
def test_collect_so_aceita_nome_que_resolve_e_respeita_skip_e_teto(monkeypatch):
    resolvidos = []

    async def fake_resolve(candidates, timeout, concurrency=50, wildcard=None, pace=None):
        resolvidos.append(list(candidates))
        return {h for h in candidates if h.startswith(("a.", "b."))}   # o resto não resolve

    async def fake_query(apex, sources, keys, timeout, transport=None):
        return {"a.acme.com", "b.acme.com", "morto.acme.com", "ja.acme.com"}, {"otx": "4 nome(s)"}

    monkeypatch.setattr(passive, "resolve_hosts", fake_resolve)
    monkeypatch.setattr(passive, "query_sources", fake_query)
    cr = asyncio.run(passive.collect(APEX, ["otx"], {}, 5, 2, skip={"ja.acme.com"}))
    assert cr.ok and sorted(r.key for r in cr.records) == ["a.acme.com", "b.acme.com"]
    assert "ja.acme.com" not in resolvidos[0]                 # já conhecido: não re-resolve
    cr = asyncio.run(passive.collect(APEX, ["otx"], {}, 5, 2, max_candidates=1))
    assert len(resolvidos[-1]) == 1                           # teto de candidatos


@pytest.mark.passive_sources
def test_collect_sem_nenhuma_fonte_respondendo_nao_e_ok(monkeypatch):
    async def fake_query(apex, sources, keys, timeout, transport=None):
        return set(), {"otx": "erro (ConnectError)", "wayback": "erro (ReadTimeout)"}

    monkeypatch.setattr(passive, "query_sources", fake_query)
    cr = asyncio.run(passive.collect(APEX, ["otx", "wayback"], {}, 5, 2))
    assert cr.ok is False and cr.records == []


# ── engine: intervalo entre consultas e falha que não atrasa a baseline ─────
def _engine_cfg(db, **col):
    return Config(targets=[APEX], db_path=db, scope_confirmed=True,
                  collectors=CollectorsConfig(
                      subdomains=True, bruteforce=False, wildcard=True, dns=False,
                      dns_records=False, http=False, tls=False, takeover=False, ports=False,
                      favicon=False, http_security=False, **col))


@pytest.mark.passive_sources
def test_engine_consulta_no_maximo_a_cada_intervalo_e_falha_e_consultiva(monkeypatch):
    chamadas = []
    respostas = iter([CollectionResult(records=[], ok=False),     # 1º: fontes fora do ar
                      CollectionResult(records=[], ok=True),      # 2º: respondeu
                      CollectionResult(records=[], ok=True)])

    async def fake_collect(target, *a, **k):
        chamadas.append(target)
        return next(respostas)

    async def fake_sub(target, client):
        return CollectionResult(records=[], ok=True, hosts={target})

    async def fake_wc(apex, timeout, probes):
        return wcmod.Wildcard(active=False)

    monkeypatch.setattr(passive, "collect", fake_collect)
    monkeypatch.setattr(submod, "collect", fake_sub)
    monkeypatch.setattr(wcmod, "detect", fake_wc)
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    try:
        eng = Engine(_engine_cfg(db), s)
        r1 = asyncio.run(eng.scan_target(APEX))
        assert r1.complete is True                     # fonte externa fora não deixa incompleta
        assert r1.collector_stats["passive"] == {"ok": 0, "fail": 1}   # mas aparece na saúde
        asyncio.run(eng.scan_target(APEX))             # falhou antes: tenta de novo
        asyncio.run(eng.scan_target(APEX))             # respondeu há pouco: não consulta
        assert len(chamadas) == 2
        s.set_meta("passive.fetched_at:" + APEX, "0")  # passou do intervalo
        asyncio.run(eng.scan_target(APEX))
        assert len(chamadas) == 3
    finally:
        s.close()
        os.remove(db)


# ── config e redação ─────────────────────────────────────────────────────────
def test_config_fontes(tmp_path, monkeypatch):
    p = tmp_path / "c.yaml"
    monkeypatch.setenv("PADME_ST_KEY", "st-123")
    p.write_text("targets: [a.com]\ncollectors:\n  passive_sources: [otx, securitytrails]\n"
                 "  passive_keys:\n    securitytrails: ${PADME_ST_KEY}\n", encoding="utf-8")
    c = Config.load(p).collectors
    assert c.passive_sources == ["otx", "securitytrails"] and c.passive_keys["securitytrails"] == "st-123"
    assert Config(targets=["a.com"]).collectors.passive_sources == ["certspotter", "otx", "wayback"]
    for bad, msg in (("passive_sources: [shodan]", "desconhecida"),
                     ("passive_sources: [virustotal]", "precisa de chave"),
                     ("passive_every_hours: 0", ">= 1")):
        p.write_text(f"targets: [a.com]\ncollectors:\n  {bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match=msg):
            Config.load(p)
    p.write_text("targets: [a.com]\ncollectors:\n  passive: false\n  passive_sources: [shodan]\n",
                 encoding="utf-8")
    assert Config.load(p).collectors.passive is False          # desligado: não valida fontes


def test_redacao_de_header_de_chave():
    assert redact("APIKEY: abc123") == "APIKEY: REDACTED"
    assert redact("{'x-apikey': 'deadbeef'}") == "{'x-apikey': 'REDACTED'}"
    assert redact("X-OTX-API-KEY=zz9") == "X-OTX-API-KEY=REDACTED"
    assert redact("a apikey é obrigatória") == "a apikey é obrigatória"
