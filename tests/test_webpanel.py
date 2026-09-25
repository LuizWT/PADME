"""Teste do painel web read-only."""

import os
import tempfile

from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.webpanel import _render, _trend_svg


def test_render():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [
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
    # a seção de tendência aparece; com 1 scan (2 added) há eventos no período
    assert "TENDÊNCIA" in out
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


def test_trend_svg_vazio_nao_quebra():
    serie = [{"day": "2026-09-20", "added": 0, "removed": 0, "changed": 0, "total": 0}]
    out = _trend_svg(serie, days=1)
    assert out.startswith("<svg") and out.endswith("</svg>")
