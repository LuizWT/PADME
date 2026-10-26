"""Ciclo de vida de finding: id estável, status, reabertura, SLA, ações (CLI,
painel com CSRF) e silêncio de notificação."""

import asyncio
import base64
import os
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from padme import scheduler
from padme.cli import main
from padme.config import Config
from padme.findings import (
    ACCEPTED,
    ACKNOWLEDGED,
    OPEN,
    RESOLVED,
    SUPPRESSED,
    derive,
    finding_id,
    human_hours,
    ids_for_record,
    is_muted,
    sla_info,
)
from padme.models import Event, EventType, Kind, Record, ScanResult
from padme.storage import Storage
from padme.webpanel import PanelServer, _render, _same_origin, make_handler

TK = {"cname": "acme.github.io", "service": "GitHub Pages", "reason": "CNAME dangling (NXDOMAIN)"}


def _takeover(host="blog.acme.com", value="GitHub Pages"):
    return {"key": host, "value": value, "metadata": dict(TK)}


def _db():
    return tempfile.mktemp(suffix=".db")


# ── identidade ───────────────────────────────────────────────────────────────
def test_finding_id_estavel_e_sem_colisao_por_separador():
    a = finding_id("acme.com", "takeover", "blog.acme.com")
    assert a == finding_id("acme.com", "takeover", "blog.acme.com") and len(a) == 16
    assert a != finding_id("acme.com", "takeover", "blog.acme.com", "X")    # código distingue
    assert finding_id("a", "b|c", "d") != finding_id("a|b", "c", "d")


def test_id_nao_muda_quando_o_valor_muda():
    # cert "expira em 6 dias" -> "5 dias": é o MESMO problema
    f6 = derive("x.com", {"cert_expiry": [{"key": "x.com:443", "value": "expira em 6 dia(s)"}]})
    f5 = derive("x.com", {"cert_expiry": [{"key": "x.com:443", "value": "expira em 5 dia(s)"}]})
    assert f6[0]["id"] == f5[0]["id"]


def test_derive_mantem_o_formato_do_painel():
    f = derive("acme.com", {"takeover": [_takeover()]})[0]
    assert (f["kind"], f["sev"], f["cls"], f["severity"]) == ("TAKEOVER", "crítico", "s-crit", "critical")
    assert f["src_kind"] == "takeover" and f["src_key"] == "blog.acme.com"
    assert "takeover_check" in f["evidence"]


# ── banco: sync com o scan ───────────────────────────────────────────────────
def test_sync_abre_resolve_e_reabre():
    db = _db()
    s = Storage(db)
    try:
        cur = derive("acme.com", {"takeover": [_takeover()]})
        fid = cur[0]["id"]
        assert s.sync_findings("acme.com", cur, now=100) == {"opened": 1, "reopened": 0, "resolved": 0}
        assert s.sync_findings("acme.com", cur, now=200)["opened"] == 0   # mesmo problema
        row = s.get_finding(fid)
        assert row["status"] == OPEN and row["first_seen"] == 100 and row["last_seen"] == 200

        assert s.sync_findings("acme.com", [], now=300)["resolved"] == 1  # sumiu do estado
        row = s.get_finding(fid)
        assert row["status"] == RESOLVED and not row["present"]

        assert s.sync_findings("acme.com", cur, now=400)["reopened"] == 1  # voltou
        row = s.get_finding(fid)
        assert row["status"] == OPEN and row["reopen_count"] == 1 and row["opened_at"] == 400
        hist = [h["to_status"] for h in s.finding_history(fid)]
        assert hist == [OPEN, RESOLVED, OPEN]
    finally:
        s.close()
        os.remove(db)


def test_silenciado_continua_silenciado_se_sumir_e_voltar():
    db = _db()
    s = Storage(db)
    try:
        cur = derive("acme.com", {"takeover": [_takeover()]})
        fid = cur[0]["id"]
        s.sync_findings("acme.com", cur, now=100)
        s.set_finding_status(fid, "suppress", reason="CNAME é nosso, página de manutenção",
                             actor="ana", now=150)
        s.sync_findings("acme.com", [], now=200)
        assert s.get_finding(fid)["status"] == SUPPRESSED     # não vira "resolvido"
        s.sync_findings("acme.com", cur, now=300)
        row = s.get_finding(fid)
        assert row["status"] == SUPPRESSED and row["reopen_count"] == 0   # mesmo falso positivo
    finally:
        s.close()
        os.remove(db)


def test_acoes_validam_e_auditam():
    db = _db()
    s = Storage(db)
    try:
        cur = derive("acme.com", {"takeover": [_takeover()]})
        fid = cur[0]["id"]
        s.sync_findings("acme.com", cur, now=100)
        row = s.set_finding_status(fid[:8], "ack", actor="ana", now=110)   # prefixo único
        assert row["status"] == ACKNOWLEDGED and row["status_by"] == "ana"
        assert row["opened_at"] == 100                     # ack NÃO para o relógio do SLA
        with pytest.raises(ValueError, match="já está"):
            s.set_finding_status(fid, "ack", actor="ana")
        with pytest.raises(ValueError, match="motivo"):
            s.set_finding_status(fid, "accept", actor="ana")   # aceitar risco exige motivo
        with pytest.raises(ValueError, match="inválida"):
            s.set_finding_status(fid, "delete", actor="ana")
        with pytest.raises(ValueError, match="não encontrado"):
            s.set_finding_status("ffffffffff", "ack")
        s.set_finding_status(fid, "accept", reason="ambiente de testes", actor="ana", now=120)
        row = s.set_finding_status(fid, "reopen", actor="bia", now=130)
        assert row["status"] == OPEN and row["opened_at"] == 130     # reabrir reinicia o prazo
        h = s.finding_history(fid)
        assert [(x["to_status"], x["actor"]) for x in h] == [
            (OPEN, "scan"), (ACKNOWLEDGED, "ana"), (ACCEPTED, "ana"), (OPEN, "bia")]
        assert h[2]["reason"] == "ambiente de testes"
        s.sync_findings("acme.com", [], now=200)
        with pytest.raises(ValueError, match="resolvido"):
            s.set_finding_status(fid, "ack")               # o scan resolveu: nada a tratar
    finally:
        s.close()
        os.remove(db)


def test_prefixo_curto_ou_invalido_nao_casa():
    db = _db()
    s = Storage(db)
    try:
        s.sync_findings("acme.com", derive("acme.com", {"takeover": [_takeover()]}), now=1)
        assert s.get_finding("abc") is None          # < 6 caracteres
        assert s.get_finding("zzzzzzzz") is None     # não é hex
        assert s.get_finding("' OR 1=1 --") is None
    finally:
        s.close()
        os.remove(db)


# ── SLA ──────────────────────────────────────────────────────────────────────
def test_sla_por_severidade():
    sla = {"critical": 24, "high": 72, "medium": 0}
    row = {"status": OPEN, "severity": "critical", "opened_at": 0}
    assert sla_info(row, 10 * 3600, sla)["breached"] is False
    late = sla_info(row, 30 * 3600, sla)
    assert late["breached"] is True and round(late["left_h"]) == -6
    assert sla_info({**row, "status": ACKNOWLEDGED}, 30 * 3600, sla)["breached"] is True  # ack não para
    assert sla_info({**row, "status": SUPPRESSED}, 30 * 3600, sla) is None
    assert sla_info({**row, "severity": "medium"}, 999 * 3600, sla)["limit_h"] == 0         # sem prazo
    assert human_hours(0.4) == "<1h" and human_hours(30) == "30h" and human_hours(50) == "2d 2h"


def test_config_sla(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: [a.com]\nfindings:\n  sla_hours:\n    critical: 4\n", encoding="utf-8")
    cfg = Config.load(p)
    assert cfg.findings.sla_hours == {"critical": 4, "high": 72, "medium": 168}
    assert cfg.web.actions is True and not cfg.warnings
    p.write_text("targets: [a.com]\nfindings:\n  sla_hours:\n    urgente: 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="desconhecida"):
        Config.load(p)
    p.write_text("targets: [a.com]\nfindings:\n  sla_hours:\n    high: -1\n", encoding="utf-8")
    with pytest.raises(ValueError, match=">= 0"):
        Config.load(p)


# ── notificação ──────────────────────────────────────────────────────────────
def test_evento_de_finding_silenciado_nao_notifica():
    tk = Event("acme.com", EventType.CHANGED, Kind.TAKEOVER, "blog.acme.com", "GitHub Pages",
               "GitHub Pages (404)", metadata=dict(TK))
    fid = ids_for_record("acme.com", "takeover", "blog.acme.com", "x", TK)[0]
    assert is_muted("acme.com", tk, {fid: SUPPRESSED}) is True
    assert is_muted("acme.com", tk, {fid: ACKNOWLEDGED}) is False   # reconhecer não silencia
    port = Event("acme.com", EventType.ADDED, Kind.PORT, "acme.com:22", None, "open")
    assert is_muted("acme.com", port, {fid: SUPPRESSED}) is False   # não é finding


def test_email_com_codigo_novo_volta_a_notificar():
    md = {"type": "dmarc"}
    key, val = "x.com|DMARC", "v=DMARC1; p=none"
    ids = ids_for_record("x.com", "mailsec", key, val, md)
    assert ids
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, key, "v=DMARC1; p=reject", val, metadata=md)
    assert is_muted("x.com", e, {i: ACCEPTED for i in ids}) is True
    assert is_muted("x.com", e, {ids[0]: ACCEPTED}) is (len(ids) == 1)


class _FakeNotifier:
    notifiers: list = []

    def __init__(self):
        self.sent = []

    def __bool__(self):
        return True

    async def dispatch(self, target, events):
        self.sent.extend(events)
        return []


def test_scan_one_sincroniza_e_silencia(monkeypatch):
    db = _db()
    scans = iter([
        [Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages", metadata=dict(TK))],
        [Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages (404)", metadata=dict(TK)),
         Record(Kind.PORT, "acme.com:22", "open")],
    ])

    async def fake_scan(self, target):
        r = ScanResult(target=target)
        r.records.extend(next(scans))
        return r

    monkeypatch.setattr("padme.engine.Engine.scan_target", fake_scan)
    cfg = Config(targets=["acme.com"], db_path=db, scope_confirmed=True)
    storage = Storage(db)
    try:
        from padme.engine import Engine
        engine = Engine(cfg, storage)
        notifier = _FakeNotifier()
        o = asyncio.run(scheduler.scan_one(cfg, engine, storage, notifier, "acme.com"))
        assert o.first and o.findings["opened"] == 1          # baseline já abre o finding
        fid = next(iter(storage.finding_rows(["acme.com"])))
        storage.set_finding_status(fid, "suppress", reason="página nossa", actor="ana")
        o = asyncio.run(scheduler.scan_one(cfg, engine, storage, notifier, "acme.com"))
        kinds = sorted(e.kind.value for e in notifier.sent)
        assert kinds == ["port"]                               # takeover mudou, mas está silenciado
        assert o.muted == 1
    finally:
        storage.close()
        os.remove(db)


# ── CLI ──────────────────────────────────────────────────────────────────────
def _cfg_file(tmp_path, db, extra=""):
    p = tmp_path / "c.yaml"
    p.write_text(f"targets: [acme.com]\ndb_path: {db}\n{extra}", encoding="utf-8")
    return str(p)


def test_cli_finding_list_ack_suppress_show(tmp_path, capsys):
    db = str(tmp_path / "p.db")
    s = Storage(db)
    s.sync_findings("acme.com", derive("acme.com", {"takeover": [_takeover()]}))
    fid = next(iter(s.finding_rows()))
    s.close()
    cfg = _cfg_file(tmp_path, db)
    assert main(["-c", cfg, "finding", "list"]) == 0
    out = capsys.readouterr().out
    assert fid[:10] in out and "aberto" in out and "TAKEOVER" in out
    assert main(["-c", cfg, "finding", "ack", fid[:8], "--by", "ana"]) == 0
    assert "reconhecido" in capsys.readouterr().out
    assert main(["-c", cfg, "finding", "suppress", fid]) == 1          # sem motivo
    assert "motivo" in capsys.readouterr().err
    assert main(["-c", cfg, "finding", "suppress", fid, "--reason", "falso positivo"]) == 0
    capsys.readouterr()
    assert main(["-c", cfg, "finding", "list"]) == 0
    assert "nenhum finding ativo" in capsys.readouterr().out             # tratado sai da lista
    assert main(["-c", cfg, "finding", "show", fid]) == 0
    out = capsys.readouterr().out
    assert "por ana" in out and "falso positivo" in out and "silenciado" in out


# ── API ──────────────────────────────────────────────────────────────────────
def test_api_lista_findings_ativos_por_padrao():
    from padme.api import _findings
    db = _db()
    s = Storage(db)
    s.sync_findings("acme.com", derive("acme.com", {"takeover": [_takeover()],
                                                    "wildcard": [{"key": "*.acme.com",
                                                                  "value": "1.2.3.4"}]}))
    ids = list(s.finding_rows())
    s.set_finding_status(ids[0], "suppress", reason="fp", actor="ana")
    s.close()
    cfg = Config(targets=["acme.com"], db_path=db)
    try:
        ativos = _findings(cfg, {})
        assert ativos["total"] == 1 and ativos["items"][0]["sla"]["limit_hours"] > 0
        todos = _findings(cfg, {"status": ["all"]})
        assert todos["total"] == 2
        assert {i["status"] for i in todos["items"]} == {OPEN, SUPPRESSED}
    finally:
        os.remove(db)


# ── painel ───────────────────────────────────────────────────────────────────
def _panel_db():
    db = _db()
    s = Storage(db)
    s.apply_scan("acme.com", [Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages",
                                     metadata=dict(TK)),
                              Record(Kind.WILDCARD, "*.acme.com", "1.2.3.4")])
    kinds: dict = {}
    for r in s.all_state(["acme.com"]):
        kinds.setdefault(r["kind"], []).append(r)
    s.sync_findings("acme.com", derive("acme.com", kinds), now=0)   # aberto há muito: prazo estourado
    s.close()
    return db


def test_painel_mostra_estado_prazo_e_tratados():
    db = _panel_db()
    s = Storage(db)
    rows = s.finding_rows()
    wild = next(fid for fid, r in rows.items() if r["kind"] == "wildcard")
    s.set_finding_status(wild, "accept", reason="curinga do CDN, esperado", actor="ana")
    s.close()
    cfg = Config(targets=["acme.com"], db_path=db)
    try:
        ro = _render(cfg)
        assert "prazo estourado" in ro and "com prazo estourado" in ro      # KPI e linha
        assert "1 tratado(s)" in ro and "curinga do CDN" in ro and "risco aceito" in ro
        assert "<form method=post" not in ro                               # sem csrf: read-only
        rw = _render(cfg, csrf="tok123")
        assert "<form method=post action='/finding'" in rw and "value='tok123'" in rw
        assert "value=reopen" in rw and "value=suppress" in rw
    finally:
        os.remove(db)


def test_same_origin():
    assert _same_origin({"Host": "127.0.0.1:8787"}) is True                       # curl: vale o token
    assert _same_origin({"Host": "127.0.0.1:8787", "Origin": "http://127.0.0.1:8787"}) is True
    assert _same_origin({"Host": "127.0.0.1:8787", "Origin": "https://evil.example"}) is False
    assert _same_origin({"Host": "127.0.0.1:8787", "Origin": "null"}) is False
    assert _same_origin({"Host": "x", "Sec-Fetch-Site": "cross-site"}) is False
    assert _same_origin({"Host": "x", "Sec-Fetch-Site": "same-origin"}) is True


def _serve(cfg, exposed=False, token=None):
    srv = PanelServer(("127.0.0.1", 0), make_handler(cfg, exposed=exposed, auth_token=token))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _post(port, fields, headers=None):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/finding", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _csrf_from_page(port, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    html = urllib.request.urlopen(req, timeout=5).read().decode()
    return html.split("name=csrf value='", 1)[1].split("'", 1)[0]


def test_post_finding_com_csrf():
    db = _panel_db()
    cfg = Config(targets=["acme.com"], db_path=db)
    s = Storage(db)
    fid = next(fid for fid, r in s.finding_rows().items() if r["kind"] == "takeover")
    s.close()
    srv, port = _serve(cfg)
    try:
        token = _csrf_from_page(port)
        code, _, _ = _post(port, {"id": fid, "action": "ack", "csrf": "errado"})
        assert code == 403                                               # CSRF inválido
        code, _, _ = _post(port, {"id": fid, "action": "ack", "csrf": token},
                           {"Origin": "https://evil.example"})
        assert code == 403                                               # origem cruzada
        code, _, body = _post(port, {"id": fid, "action": "accept", "csrf": token})
        assert code == 400 and "motivo" in body                          # validação do storage
        code, hdr, _ = _post(port, {"id": fid, "action": "ack", "csrf": token,
                                    "target": "acme.com\r\nX-Evil: 1"})
        assert code == 303 and hdr["Location"].startswith("/?target=acme.com%0D%0AX-Evil")
        s = Storage(db)
        row = s.get_finding(fid)
        s.close()
        assert row["status"] == ACKNOWLEDGED and row["status_by"] == "painel"
    finally:
        srv.shutdown()
        srv.server_close()
        os.remove(db)


def test_post_desligado_quando_exposto_sem_token_ou_actions_false():
    db = _panel_db()
    cfg = Config(targets=["acme.com"], db_path=db)
    srv, port = _serve(cfg, exposed=True, token=None)
    try:
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read().decode()
        assert "<form method=post" not in html
        assert _post(port, {"id": "x", "action": "ack", "csrf": ""})[0] == 403
    finally:
        srv.shutdown()
        srv.server_close()
    cfg.web.actions = False
    srv, port = _serve(cfg)
    try:
        assert _post(port, {"id": "x", "action": "ack", "csrf": ""})[0] == 403
    finally:
        srv.shutdown()
        srv.server_close()
        os.remove(db)


def test_post_com_token_exige_auth_e_registra_usuario():
    db = _panel_db()
    cfg = Config(targets=["acme.com"], db_path=db)
    s = Storage(db)
    fid = next(fid for fid, r in s.finding_rows().items() if r["kind"] == "takeover")
    s.close()
    srv, port = _serve(cfg, exposed=True, token="sekret")
    basic = {"Authorization": "Basic " + base64.b64encode(b"ana:sekret").decode()}
    try:
        assert _post(port, {"id": fid, "action": "ack", "csrf": "x"})[0] == 401   # sem login
        token = _csrf_from_page(port, basic)
        code, _, _ = _post(port, {"id": fid, "action": "ack", "csrf": token}, basic)
        assert code == 303
        s = Storage(db)
        assert s.get_finding(fid)["status_by"] == "ana"     # usuário do login vai p/ a auditoria
        s.close()
    finally:
        srv.shutdown()
        srv.server_close()
        os.remove(db)


def test_fila_de_reenvio_descarta_finding_silenciado_depois_da_falha():
    db = _db()
    s = Storage(db)
    try:
        s.apply_scan("acme.com", [])                                   # baseline
        evs = s.apply_scan("acme.com", [Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages",
                                               metadata=dict(TK))])
        s.queue_notifications("telegram", "acme.com", [evs[0].event_id])   # o envio tinha falhado
        counts, _ = scheduler.sync_target_findings(s, "acme.com")
        assert counts["opened"] == 1
        fid = next(iter(s.finding_rows()))
        s.set_finding_status(fid, "suppress", reason="falso positivo", actor="ana")

        class Canal:
            name = "telegram"
            enviados: list = []

            async def notify_events(self, target, events):
                self.enviados.extend(events)

        canal = Canal()
        mgr = type("M", (), {"notifiers": [canal]})()
        asyncio.run(scheduler.retry_pending(s, mgr))
        assert canal.enviados == []                          # não reenvia o silenciado
        assert s.pending_notifications("telegram") == []     # e tira da fila
    finally:
        s.close()
        os.remove(db)
