"""Base de takeover gerada do can-i-take-over-xyz: regras de conversão,
assinatura como regex, especificidade do CNAME e confiança por status."""

import asyncio
import importlib.util
import re
from pathlib import Path

from padme.collectors import takeover
from padme.models import Event, EventType, Kind
from padme.risk import Confidence, assess

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "update_takeover_fingerprints.py"
_spec = importlib.util.spec_from_file_location("update_fp", _SCRIPT)
update_fp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_fp)


# ── a base empacotada ───────────────────────────────────────────────────────
def test_base_so_tem_servicos_reivindicaveis_e_regex_valida():
    assert takeover.FINGERPRINTS
    for s in takeover.FINGERPRINTS:
        assert s["status"] in ("vulnerable", "edge case"), s["service"]
        assert s["cnames"], s["service"]
        assert s["nxdomain"] or s["fingerprint"], s["service"]
        re.compile(s["fingerprint"])
    nomes = {s["service"] for s in takeover.FINGERPRINTS}
    # o upstream marca como NÃO vulneráveis: fora (eram alerta crítico falso)
    assert not nomes & {"Fastly", "Zendesk"}


def _run(monkeypatch, cname, body):
    async def fake_cname(h, t):
        return cname, True, True

    async def fake_body(client, h, cache=None, follow_redirects=False, max_bytes=0,
                        allow_private=False):
        return body, True

    monkeypatch.setattr(takeover, "_cname_target", fake_cname)
    monkeypatch.setattr(takeover, "_body", fake_body)
    return asyncio.run(takeover.collect_host("x.alvo.com", client=None, timeout=5)).records


def test_assinatura_regex_do_upstream(monkeypatch):
    recs = _run(monkeypatch, "abc.ngrok.io", "<h1>Tunnel abc.ngrok.io not found</h1>")
    assert len(recs) == 1 and recs[0].metadata["service"] == "Ngrok"
    assert _run(monkeypatch, "abc.ngrok.io", "<h1>ok</h1>") == []


def test_assinatura_curada_segue_valendo(monkeypatch):
    recs = _run(monkeypatch, "b.s3.amazonaws.com", "<Code>NoSuchBucket</Code>")
    assert len(recs) == 1 and recs[0].metadata["service"] == "AWS S3"


def test_edge_case_baixa_confianca(monkeypatch):
    recs = _run(monkeypatch, "u.github.io", "There isn't a GitHub Pages site here.")
    assert recs[0].metadata["status"] == "edge case"
    ev = Event("alvo.com", EventType.ADDED, Kind.TAKEOVER, recs[0].key,
               new_value=recs[0].value, metadata=recs[0].metadata)
    assert assess(ev).confidence == Confidence.MEDIUM


def test_sufixo_mais_especifico_vence(monkeypatch):
    base = [
        {"service": "Amplo", "cnames": ["exemplo.net"], "fingerprint": "a", "nxdomain": False},
        {"service": "Especifico", "cnames": ["cdn.exemplo.net"], "fingerprint": "b",
         "nxdomain": False},
    ]
    monkeypatch.setattr(takeover, "FINGERPRINTS", base)
    assert takeover.match_service("x.cdn.exemplo.net")["service"] == "Especifico"
    assert takeover.match_service("x.www.exemplo.net")["service"] == "Amplo"


# ── conversão do upstream ───────────────────────────────────────────────────
def _entry(service, status, cname, fingerprint, nxdomain=False):
    return {"service": service, "status": status, "cname": cname,
            "fingerprint": fingerprint, "nxdomain": nxdomain}


def test_conversao_do_upstream():
    upstream = [
        _entry("Fora", "Not vulnerable", ["fora.com"], "x"),
        _entry("SoStatus", "Vulnerable", ["st.com"], "HTTP_STATUS=500"),
        _entry("SemCname", "Vulnerable", [], "algo"),
        _entry("Ips", "Vulnerable", ["52.16.160.97", "https://x.io/", "ok.io"], "Não achei (x)"),
        _entry("Alternativas", "Edge case", ["alt.io"], "Primeira` `Segunda"),
        _entry("Tabela", "Vulnerable", ["tab.io"], "Um\\.&#124;Dois"),
        _entry("Nx", "Vulnerable", ["nx.net"], "NXDOMAIN", nxdomain=True),
        _entry("Github", "Edge case", [], "There isn't a GitHub Pages site here."),
    ]
    services, skipped = update_fp.convert(upstream)
    by = {s["service"]: s for s in services}
    assert set(by) == {"Ips", "Alternativas", "Tabela", "Nx", "GitHub Pages"}
    assert by["Ips"]["cnames"] == ["ok.io"]                    # IP e URL descartados
    assert re.search(by["Ips"]["fingerprint"], "Não achei (x)")  # literal escapado
    assert by["Alternativas"]["status"] == "edge case"
    assert re.search(by["Alternativas"]["fingerprint"], "... Segunda ...")
    assert re.search(by["Tabela"]["fingerprint"], "Dois")       # &#124; = alternância
    assert by["Nx"]["nxdomain"] and by["Nx"]["fingerprint"] == ""
    assert by["GitHub Pages"]["cnames"] == ["github.io"]        # completado pela curadoria
    assert any("SoStatus" in s for s in skipped) and any("SemCname" in s for s in skipped)
