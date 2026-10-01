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


def test_render_mostra_service_product_version_da_porta():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [
        Record(Kind.PORT, "alvo.com:22", "open · SSH-2.0-OpenSSH_9.6p1",
               metadata={"port": 22, "banner": "SSH-2.0-OpenSSH_9.6p1",
                         "service": "ssh", "product": "OpenSSH", "version": "9.6p1"}),
    ])
    s.close()
    cfg = Config(targets=["alvo.com"], db_path=db)
    out = _render(cfg)
    os.remove(db)
    # o que antes só ia na evidência/webhook agora aparece na linha do ativo
    assert "class=fp" in out
    assert ">ssh<" in out
    assert "OpenSSH 9.6p1" in out


def test_port_fp_sem_service_nem_product_vazio():
    from padme.webpanel import _port_fp
    assert _port_fp({"port": 4444, "banner": "algo-proprietario"}) == ""
    assert _port_fp(None) == ""
    # só service (porta conhecida, banner sem produto) já rende badge
    assert "svc" in _port_fp({"service": "redis"})


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


def test_explainability_conta_os_tres_pilares():
    from padme.models import Event, EventType, Kind
    from padme.webpanel import _explainability
    # takeover (CRITICAL) completo: razão + proveniência (_collector) + evidência
    ok = Event("a.com", EventType.ADDED, Kind.TAKEOVER, "blog.a.com", None, "GitHub Pages",
               metadata={"_collector": "takeover", "cname": "x.github.io", "reason": "NXDOMAIN"})
    # idêntico, mas SEM proveniência -> não conta como explicável
    sem_prov = Event("a.com", EventType.ADDED, Kind.TAKEOVER, "shop.a.com", None, "GitHub Pages",
                     metadata={"cname": "y.github.io", "reason": "NXDOMAIN"})
    res = _explainability({"a.com": [ok, sem_prov]})
    assert res["high"] == 2 and res["explained"] == 1 and res["pct"] == 50
    assert "proveniência" in res["missing"]


def test_explainability_none_sem_evento_grave():
    from padme.models import Event, EventType, Kind
    from padme.webpanel import _explainability
    baixo = Event("a.com", EventType.ADDED, Kind.DNS, "a.com|A|1.2.3.4", None, "1.2.3.4",
                  metadata={"_collector": "dns"})
    assert _explainability({"a.com": [baixo]}) is None


def test_render_mostra_kpi_de_explicabilidade():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [])  # baseline
    s.apply_scan("alvo.com", [    # takeover CRITICAL com metadata -> evento explicável
        Record(Kind.TAKEOVER, "blog.alvo.com", "GitHub Pages",
               metadata={"cname": "alvo.github.io", "reason": "CNAME dangling (NXDOMAIN)"}),
    ])
    s.close()
    out = _render(Config(targets=["alvo.com"], db_path=db))
    os.remove(db)
    assert "alertas explicáveis" in out


def test_collector_reliability_consolida_e_aponta_degradado():
    from padme.webpanel import _collector_reliability
    meta = {
        "a.com": {"collectors_health": {
            "dns": {"status": "ok"}, "http": {"status": "ok"},
            "tls": {"status": "error"}}},
        "b.com": {"collectors_health": {
            "dns": {"status": "ok"}, "ports": {"status": "partial"}}},
    }
    rel = _collector_reliability(meta)
    assert rel["total"] == 5 and rel["ok"] == 3 and rel["pct"] == 60
    assert rel["has_error"] is True
    # tls (error) vem antes de ports (partial) na lista de degradados
    assert rel["degraded"][0] == "tls" and "ports" in rel["degraded"]


def test_collector_reliability_none_sem_saude():
    from padme.webpanel import _collector_reliability
    assert _collector_reliability({"a.com": {}}) is None
    assert _collector_reliability({}) is None


def test_render_mostra_kpi_de_collectors():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [Record(Kind.SUBDOMAIN, "api.alvo.com", "live")])
    s.update_health("alvo.com", error_count=0, partial=False, duration_ms=10,
                    collectors={"dns": {"status": "ok"}, "http": {"status": "ok"}})
    s.close()
    out = _render(Config(targets=["alvo.com"], db_path=db))
    os.remove(db)
    assert "collectors confiáveis" in out


def test_trend_svg_vazio_nao_quebra():
    serie = [{"day": "2026-09-20", "added": 0, "removed": 0, "changed": 0, "total": 0}]
    out = _trend_svg(serie, days=1)
    assert out.startswith("<svg") and out.endswith("</svg>")


def test_prioritize_events_por_relevancia():
    from padme.models import Event, EventType, Kind
    from padme.webpanel import _prioritize_events
    # DNS (DEBUG) mais recente vs TAKEOVER (CRITICAL) mais antigo
    dns_novo = Event("a.com", EventType.CHANGED, Kind.DNS, "a.com|A|1.2.3.4",
                     "1.1.1.1", "1.2.3.4", detected_at="2026-09-29T10:00:00+00:00")
    takeover_antigo = Event("a.com", EventType.ADDED, Kind.TAKEOVER, "blog.a.com",
                            None, "GitHub Pages", detected_at="2026-09-27T10:00:00+00:00")
    ordem = _prioritize_events([dns_novo, takeover_antigo])
    # o crítico (mesmo mais antigo) vem primeiro; o debug recente, por último
    assert ordem[0][0].kind == Kind.TAKEOVER
    assert ordem[-1][0].kind == Kind.DNS


def test_problems_panel_mostra_evidencia():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    # takeover no estado atual -> vira cartão de "problema aberto"
    s.apply_scan("acme.com", [
        Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages",
               metadata={"cname": "acme.github.io", "service": "GitHub Pages",
                         "reason": "CNAME dangling (NXDOMAIN)"}),
    ])
    s.close()
    out = _render(Config(targets=["acme.com"], db_path=db))
    os.remove(db)
    assert "problemas abertos" in out
    # a prova normalizada aparece no cartão agregado (não só na timeline)
    assert "prova:" in out and "takeover_check" in out and "NXDOMAIN" in out


# ── correções do painel (tile zero, filtro, persistência) ────────────────────
def test_esc_preserva_zero_e_false():
    from padme.webpanel import _esc
    assert _esc(0) == "0"          # 0 NÃO vira "" (tile de portas abertas)
    assert _esc(False) == "False"
    assert _esc(None) == ""        # só None é vazio
    assert _esc("<x>") == "&lt;x&gt;"


def test_stat_tile_zero_portas_mostra_zero():
    from padme.webpanel import _stat_tiles
    html = _stat_tiles({"http": [{"key": "https://a.com", "value": "200"}]})  # sem 'port'
    assert "<div class=num>0</div><div class=lab>portas abertas</div>" in html


def test_render_tem_filtro_e_details_persistente():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [])
    s.apply_scan("a.com", [Record(Kind.PORT, "a.com:3389", "open", metadata={"port": 3389})])
    s.close()
    out = _render(Config(targets=["a.com"], db_path=db))
    assert "data-persist='k-a-com'" in out       # estado do <details> persiste no refresh
    assert "class=kfilter" in out                # caixa de busca por categoria
    assert "data-kind='port'" in out             # grupo marcado p/ a busca casar o kind
    # auto-refresh é por JS (pausável), NÃO <meta refresh> (que apagava o filtro)
    assert "http-equiv=refresh" not in out
    assert "id=autopill" in out and "data-secs=30" in out
