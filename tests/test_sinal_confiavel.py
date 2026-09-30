"""Mudanças falsas e alertas errados (itens 1–5 da revisão de gaps).

Cada teste fixa um caso em que o PADME gerava sinal sem evidência: liveness que
virava 'quiet' por timeout, subdomínio removido porque a descoberta falhou,
baseline parcial virando enxurrada de ADDED e resolução alertada com a
gravidade do problema."""

import asyncio
import os
import tempfile

from padme.cli import _print_events
from padme.collectors import dns as dnsmod
from padme.collectors import subdomains as submod
from padme.collectors import wildcard as wcmod
from padme.config import CollectorsConfig, Config
from padme.engine import Engine, annotate_liveness, carry_forward_subdomains
from padme.evidence import evidence_of
from padme.levels import ISSUE_RESOLVED, Level, assess
from padme.models import CollectionResult, Event, EventType, Kind, Record, ScanResult
from padme.storage import Storage
from padme.webpanel import _explainability

SUB = Kind.SUBDOMAIN


def _subs(records):
    return {r.key: r.value for r in records if r.kind == SUB}


# ── 1. liveness só muda com prova ───────────────────────────────────────────
def test_timeout_de_http_mantem_live_anterior():
    # HTTP do host deu timeout: nenhum escopo ativo observado -> não inventa quiet
    recs = [Record(SUB, "api.x.com")]
    out = annotate_liveness(recs, observed=set(), previous={"api.x.com": "live"})
    assert _subs(out) == {"api.x.com": "live"}


def test_dns_que_parou_de_resolver_prova_quiet():
    recs = [Record(SUB, "api.x.com")]
    out = annotate_liveness(recs, observed={("dns", "api.x.com")},
                            previous={"api.x.com": "live"})
    assert _subs(out) == {"api.x.com": "quiet"}


def test_todos_os_ativos_observados_sem_servico_prova_quiet():
    # só TLS ligado, observado (conexão recusada) e sem cert -> negativa autoritativa
    recs = [Record(SUB, "api.x.com"), Record(Kind.DNS, "api.x.com|A|1.2.3.4", "1.2.3.4")]
    out = annotate_liveness(recs, observed={("tls", "api.x.com"), ("dns", "api.x.com")},
                            previous={"api.x.com": "live"}, live_kinds=(Kind.TLS,))
    assert _subs(out) == {"api.x.com": "quiet"}


def test_evidencia_positiva_vira_live_e_metadata_preservado():
    recs = [Record(SUB, "api.x.com", metadata={"src": "ct"}),
            Record(Kind.HTTP, "https://api.x.com", "200 | nginx |")]
    out = annotate_liveness(recs, observed={("http", "api.x.com")}, previous={})
    sub = next(r for r in out if r.kind == SUB)
    assert sub.value == "live" and sub.metadata == {"src": "ct"}


def test_host_novo_sem_prova_comeca_quiet():
    out = annotate_liveness([Record(SUB, "novo.x.com")], observed=set(), previous={})
    assert _subs(out) == {"novo.x.com": "quiet"}


# ── 2/3. subdomínio conhecido só sai com prova de DNS ───────────────────────
def test_descoberta_vazia_mantem_conhecidos():
    # CT voltou vazio / bruteforce não achou: o conhecido é mantido
    out = carry_forward_subdomains([], set(), {"a.x.com": "live", "b.x.com": "quiet"})
    assert _subs(out) == {"a.x.com": "live", "b.x.com": "quiet"}


def test_dns_inconclusivo_mantem_conhecido():
    # DNS do host deu timeout (escopo não observado) -> não é prova de sumiço
    out = carry_forward_subdomains([], set(), {"a.x.com": "live"})
    assert "a.x.com" in _subs(out)


def test_dns_observado_sem_registro_remove():
    out = carry_forward_subdomains([], {("dns", "a.x.com")}, {"a.x.com": "live"})
    assert _subs(out) == {}


def test_nao_duplica_quem_a_descoberta_trouxe():
    out = carry_forward_subdomains([Record(SUB, "a.x.com")], set(), {"a.x.com": "live"})
    assert [r.key for r in out if r.kind == SUB] == ["a.x.com"]


def _cfg(db):
    return Config(targets=["alvo.com"], db_path=db, scope_confirmed=True,
                  collectors=CollectorsConfig(
                      subdomains=True, bruteforce=False, wildcard=True, dns=True,
                      dns_records=False, http=False, tls=False, takeover=False, ports=False))


def test_engine_ct_vazio_nao_apaga_e_dns_prova_remocao(monkeypatch):
    """Ponta a ponta: o CT some com o subdomínio e o DNS dele falha -> nada
    muda; o DNS observa que o nome não resolve mais -> REMOVED real."""
    scan = {"n": 0}
    ct_hosts = {1: {"api.alvo.com"}, 2: set(), 3: set()}
    dns_api = {
        1: CollectionResult([Record(Kind.DNS, "api.alvo.com|A|1.2.3.4", "1.2.3.4")], ok=True),
        2: CollectionResult([], ok=False),   # timeout: inconclusivo
        3: CollectionResult([], ok=True),    # observado e sem registro: sumiu
    }
    dns_calls: list[str] = []

    async def fake_sub(target, client):
        hs = ct_hosts[scan["n"]]
        return CollectionResult([Record(SUB, h) for h in hs], ok=True, hosts={target} | hs)

    async def fake_wc(apex, timeout, probes):
        return wcmod.Wildcard(active=False)

    async def fake_dns(host, timeout):
        dns_calls.append(host)
        return dns_api[scan["n"]] if host == "api.alvo.com" else CollectionResult([], ok=True)

    monkeypatch.setattr(submod, "collect", fake_sub)
    monkeypatch.setattr(wcmod, "detect", fake_wc)
    monkeypatch.setattr(dnsmod, "collect_host", fake_dns)

    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    eng = Engine(_cfg(db), s)
    try:
        scan["n"] = 1
        assert eng.apply(asyncio.run(eng.scan_target("alvo.com"))) == []   # baseline

        scan["n"] = 2
        dns_calls.clear()
        assert eng.apply(asyncio.run(eng.scan_target("alvo.com"))) == []
        assert "api.alvo.com" in dns_calls          # conhecido segue monitorado sem o CT
        assert ("subdomain", "api.alvo.com") in s.load_state("alvo.com")

        scan["n"] = 3
        evs = eng.apply(asyncio.run(eng.scan_target("alvo.com")))
        removed = {(e.kind.value, e.key) for e in evs if e.event_type == EventType.REMOVED}
        assert ("subdomain", "api.alvo.com") in removed
    finally:
        s.close()
        os.remove(db)


# ── 4. baseline parcial fica provisória ─────────────────────────────────────
def test_baseline_parcial_e_provisoria_e_consolida_na_repeticao():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    try:
        assert s.apply_scan("x.com", [Record(SUB, "a.x.com", "live")], complete=False) == []
        assert s.is_known_target("x.com") is False            # ainda provisória
        # 2ª tentativa: ainda baseline (sem eventos), soma o que faltou e consolida
        evs = s.apply_scan("x.com", [Record(SUB, "b.x.com", "live")], complete=False)
        assert evs == [] and s.is_known_target("x.com") is True
        assert {k for _, k in s.load_state("x.com")} == {"a.x.com", "b.x.com"}
    finally:
        s.close()
        os.remove(db)


def test_baseline_completa_consolida_de_primeira():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    try:
        s.apply_scan("x.com", [Record(SUB, "a.x.com", "live")], complete=True)
        assert s.is_known_target("x.com") is True
    finally:
        s.close()
        os.remove(db)


def test_scanresult_complete_considera_collector_inconclusivo():
    r = ScanResult(target="x.com")
    r.mark_collector("dns", True)
    assert r.complete is True
    r.mark_collector("http", False)              # timeout: ok=False sem exceção
    assert r.complete is False


def test_scan_baseline_mostra_total_real(capsys):
    _print_events("x.com", [], baseline=True, total=7)
    assert "7 itens" in capsys.readouterr().out
    _print_events("x.com", [], baseline=True, total=3, provisional=True)
    assert "PROVISÓRIA" in capsys.readouterr().out


# ── 5. resolução não é alertada com a gravidade do problema ─────────────────
def _ev(kind, etype, key="x.com", old="a", new="b", md=None):
    return Event("x.com", etype, kind, key, old, new, metadata=md or {})


def test_takeover_corrigido_e_aviso_medio_com_razao():
    # chega aos canais padrão (medium) como aviso de resolução, não como crítico
    r = assess(_ev(Kind.TAKEOVER, EventType.REMOVED, "blog.x.com", new=None))
    assert r.level == Level.MEDIUM and ISSUE_RESOLVED in r.reasons
    assert assess(_ev(Kind.TAKEOVER, EventType.ADDED, "blog.x.com", old=None)).level == Level.CRITICAL
    assert assess(_ev(Kind.TAKEOVER, EventType.CHANGED, "blog.x.com")).level == Level.CRITICAL


def test_cert_renovado_e_baixo_mas_escalada_segue_alta():
    r = assess(_ev(Kind.CERT_EXPIRY, EventType.REMOVED, "x.com:443", new=None))
    assert r.level == Level.LOW and ISSUE_RESOLVED in r.reasons
    assert assess(_ev(Kind.CERT_EXPIRY, EventType.CHANGED, "x.com:443")).level == Level.HIGH


def test_wildcard_so_alerta_quando_aparece():
    assert assess(_ev(Kind.WILDCARD, EventType.ADDED, old=None)).level == Level.HIGH
    assert assess(_ev(Kind.WILDCARD, EventType.CHANGED, old="1.1.1.1", new="1.1.1.2")).level == Level.LOW
    assert assess(_ev(Kind.WILDCARD, EventType.REMOVED, new=None)).level == Level.LOW


def test_resolucao_nao_derruba_kpi_de_explicabilidade():
    resolvido = _ev(Kind.TAKEOVER, EventType.REMOVED, "blog.x.com", new=None)
    assert _explainability({"x.com": [resolvido]}) is None   # não é alerta grave


def test_mailsec_removido_tem_evidencia():
    ev = evidence_of(Kind.MAILSEC, "x.com|SPF", "v=spf1 -all", {})
    assert ev == {"type": "dns_txt", "record": "spf", "policy": "v=spf1 -all"}


# ── coleta parcial x inconclusiva (decisão: separar os dois casos) ──────────
def test_inconclusivo_conta_separado_do_erro():
    from padme.engine import _absorb
    r = ScanResult(target="x.com")
    _absorb(CollectionResult([], ok=False), r, "http", "a.x.com")              # timeout
    _absorb(CollectionResult([], ok=False, error="boom"), r, "tls", "a.x.com")  # exceção (_safe)
    _absorb(CollectionResult([], ok=True), r, "dns", "a.x.com")
    assert r.inconclusive == 1       # só o timeout; a exceção é erro, não inconclusivo


def test_saude_persiste_inconclusivos_e_migra_para_v6():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    try:
        assert s._conn.execute("PRAGMA user_version").fetchone()[0] == 6
        s.apply_scan("x.com", [])
        s.update_health("x.com", error_count=0, partial=False, duration_ms=5, inconclusive=3)
        m = s.target_meta("x.com")
        assert m["last_inconclusive"] == 3 and m["last_partial"] == 0
    finally:
        s.close()
        os.remove(db)


def test_painel_mostra_coleta_ok_com_inconclusivos():
    from padme.webpanel import _health
    base = {"last_error_count": 0, "last_partial": 0, "last_scan_at": 0, "last_success_at": 0}
    assert "coleta ok · 3 inconclusivos" in _health({**base, "last_inconclusive": 3})
    assert "coleta ok · 1 inconclusivo<" in _health({**base, "last_inconclusive": 1})
    assert "dados completos" in _health({**base, "last_inconclusive": 0})
    # parcial de verdade continua sendo só erro (exceção)
    parcial = _health({**base, "last_error_count": 2, "last_partial": 1, "last_inconclusive": 3})
    assert "dados parciais" in parcial and "coleta ok" not in parcial


def test_doctor_mostra_inconclusivos(capsys):
    from padme.cli import _cmd_doctor
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [])
    s.update_health("x.com", error_count=0, partial=False, duration_ms=5, inconclusive=2)
    s.close()
    try:
        asyncio.run(_cmd_doctor(Config(targets=["x.com"], db_path=db), None))
        assert "inconclusivos=2" in capsys.readouterr().out
    finally:
        os.remove(db)
