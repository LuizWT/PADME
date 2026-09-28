"""Teste do painel web read-only."""

import json
import os
import tempfile

from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.webpanel import _render, _trend_svg, render_export


def test_render_export():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [Record(Kind.TLS, "a.com:443", "issuer=LE", metadata={"issuer": "LE"})])
    s.close()
    cfg = Config(targets=["a.com"], db_path=db, source="casa")
    jbody, jct = render_export(cfg, None, "json")
    cbody, cct = render_export(cfg, None, "csv")
    os.remove(db)
    data = json.loads(jbody)
    assert jct.startswith("application/json")
    assert data and data[0]["source"] == "casa" and data[0]["metadata"] == {"issuer": "LE"}
    assert cct.startswith("text/csv")
    assert cbody.splitlines()[0] == "source,target,kind,key,value,first_seen,last_seen,metadata"
    assert "casa" in cbody


def test_render():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [])   # baseline (não gera evento)
    s.apply_scan("alvo.com", [     # 2º scan: 2 ADDED reais
        Record(Kind.PORT, "alvo.com:443", "open"),
        Record(Kind.SUBDOMAIN, "api.alvo.com", ""),
    ])
    s.close()
    cfg = Config(targets=["alvo.com"], db_path=db)
    out = _render(cfg)
    os.remove(db)
    assert "alvo.com" in out
    assert "PORT" in out and "alvo.com:443" in out
    assert "<html" in out.lower()
    # visão geral + problemas + tendência (atividade != crescimento, §51)
    assert "visão geral" in out
    assert "problemas abertos" in out
    assert "tendência" in out
    assert "líquido" in out
    assert "<svg" in out
    # stat tiles da superfície atual
    assert "class=tiles" in out
    assert "subdomínios" in out and "portas abertas" in out


def test_stat_tiles_destaca_criticos():
    from padme.webpanel import _stat_tiles
    kinds = {
        "subdomain": [{"key": "a.x.com", "value": "live"},
                      {"key": "b.x.com", "value": "quiet"}],
        "takeover": [{"key": "c.x.com", "value": "GitHub Pages"}],
        "wildcard": [{"key": "x.com", "value": "1.2.3.4"}],
    }
    html = _stat_tiles(kinds)
    assert "1 live · 1 quiet" in html
    assert "tile crit" in html          # takeover destacado
    assert "tile warn" in html          # wildcard destacado
    # sem cert_expiry -> não deve aparecer o tile de cert
    assert "cert expirando" not in html


def test_events_per_day_serie_densa():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [])   # baseline (não gera evento)
    # 2 records novos -> 2 eventos ADDED hoje
    s.apply_scan("alvo.com", [
        Record(Kind.SUBDOMAIN, "api.alvo.com", ""),
        Record(Kind.PORT, "alvo.com:443", "open"),
    ])
    serie = s.events_per_day("alvo.com", days=7)
    s.close()
    os.remove(db)
    assert len(serie) == 7                      # série densa: 7 dias
    assert serie[-1]["added"] == 2              # hoje é o último
    assert serie[-1]["total"] == 2
    assert sum(d["total"] for d in serie[:-1]) == 0  # dias anteriores zerados


def test_render_filtro_por_dominio():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [Record(Kind.PORT, "a.com:443", "open")])
    s.apply_scan("b.com", [Record(Kind.SUBDOMAIN, "x.b.com", "live")])
    s.close()
    cfg = Config(targets=["a.com", "b.com"], db_path=db)
    full = _render(cfg)
    only_a = _render(cfg, only="a.com")
    os.remove(db)
    assert "a.com" in full and "b.com" in full
    assert "class=filterform" in full           # dropdown de filtro (datalist)
    assert "<datalist" in full and "id=targetlist" in full
    assert "/export?fmt=json" in full and "/export?fmt=csv" in full  # exportar
    assert "a.com:443" in only_a
    assert "x.b.com" not in only_a              # b.com filtrado fora


def test_render_mostra_evidencia_em_added():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [])   # baseline
    s.apply_scan("alvo.com", [     # ADDED com metadata -> vira evidência no painel
        Record(Kind.PORT, "alvo.com:3389", "open", metadata={"port": 3389, "banner": "xrdp"}),
    ])
    s.close()
    out = _render(Config(targets=["alvo.com"], db_path=db))
    os.remove(db)
    assert "prova:" in out and "tcp_connect" in out


def test_trend_svg_vazio_nao_quebra():
    serie = [{"day": "2026-09-20", "added": 0, "removed": 0, "changed": 0, "total": 0}]
    out = _trend_svg(serie, days=1)
    assert out.startswith("<svg") and out.endswith("</svg>")
