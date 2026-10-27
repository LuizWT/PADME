"""Resumo periódico: agenda, período, conteúdo, envio por canal e CLI."""

import asyncio
import os
import tempfile
import time
from datetime import datetime

import pytest

from padme import digest, scheduler
from padme.cli import main
from padme.config import Config, DigestConfig
from padme.findings import derive
from padme.models import Kind, Record
from padme.notify.base import NotificationManager, NotificationResult
from padme.notify.email import EmailNotifier
from padme.notify.telegram import TelegramNotifier
from padme.notify.webhook import DiscordNotifier, WebhookNotifier
from padme.storage import Storage

TK = {"cname": "acme.github.io", "service": "GitHub Pages", "reason": "CNAME dangling (NXDOMAIN)"}


def _cfg(db, **dg):
    return Config(targets=["acme.com", "quiet.dev"], db_path=db,
                  digest=DigestConfig(**{"enabled": True, **dg}))


# ── agenda ───────────────────────────────────────────────────────────────────
def test_slots_diario_e_semanal():
    now = datetime(2026, 10, 28, 8, 30)          # quarta, 08:30
    assert digest.last_slot(now, "daily", 9, "mon") == datetime(2026, 10, 27, 9)
    assert digest.next_slot(now, "daily", 9, "mon") == datetime(2026, 10, 28, 9)
    assert digest.last_slot(datetime(2026, 10, 28, 9, 0), "daily", 9, "mon") == datetime(2026, 10, 28, 9)
    assert digest.last_slot(now, "weekly", 9, "mon") == datetime(2026, 10, 26, 9)   # segunda
    assert digest.last_slot(now, "weekly", 9, "wed") == datetime(2026, 10, 21, 9)   # antes das 9h
    assert digest.next_slot(now, "weekly", 9, "wed") == datetime(2026, 10, 28, 9)


def test_due_primeiro_uso_so_marca_e_depois_respeita_o_horario():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    cfg = _cfg(db, hour=9)
    try:
        assert digest.due(cfg, s, datetime(2026, 10, 28, 15)) == (False, None)   # só agenda
        assert s.get_meta("digest.last_sent_at") is not None
        assert digest.due(cfg, s, datetime(2026, 10, 28, 20))[0] is False      # mesmo dia
        ok, start = digest.due(cfg, s, datetime(2026, 10, 29, 9, 5))
        assert ok and start == datetime(2026, 10, 28, 15).timestamp()           # desde o último
        s.set_meta("digest.last_sent_at", str(datetime(2026, 10, 29, 9, 5).timestamp()))
        assert digest.due(cfg, s, datetime(2026, 10, 29, 23))[0] is False
        cfg.digest.enabled = False
        assert digest.due(cfg, s, datetime(2026, 11, 5, 9))[0] is False
        assert digest.seconds_until_next(cfg) is None
    finally:
        s.close()
        os.remove(db)


# ── conteúdo ─────────────────────────────────────────────────────────────────
def _populated(db):
    s = Storage(db)
    s.apply_scan("acme.com", [])
    s.apply_scan("quiet.dev", [])
    s.apply_scan("acme.com", [
        Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages", metadata=dict(TK)),
        Record(Kind.PORT, "acme.com:3389", "open", metadata={"port": 3389}),
        Record(Kind.WILDCARD, "*.acme.com", "1.2.3.4"),
        Record(Kind.DNS, "acme.com|A", "1.1.1.1", metadata={"values": ["1.1.1.1"]}),
    ])
    for t in ("acme.com", "quiet.dev"):
        s.update_health(t, error_count=0, partial=False, duration_ms=5)
    kinds: dict = {}
    for r in s.all_state(["acme.com"]):
        kinds.setdefault(r["kind"], []).append(r)
    s.sync_findings("acme.com", derive("acme.com", kinds))
    wild = next(f for f, r in s.finding_rows().items() if r["kind"] == "wildcard")
    s.set_finding_status(wild, "accept", reason="CDN", actor="ana")
    return s


def test_build_conta_sem_dns_e_respeita_o_ciclo_de_vida():
    db = tempfile.mktemp(suffix=".db")
    s = _populated(db)
    try:
        data = digest.build(_cfg(db), s, time.time() - 3600)
        acme, quiet = data["targets"]
        assert acme["changes"] == {"added": 3, "changed": 0, "removed": 0}   # DNS fora
        assert acme["open"] == 1 and acme["open_by_severity"] == {"critical": 1}
        assert acme["treated"] == 1                                         # wildcard aceito
        assert len(acme["new"]) == 1 and "TAKEOVER" in acme["new"][0]
        kinds = [h["kind"] for h in acme["highlights"]]
        assert "takeover" in kinds and "port" in kinds and "wildcard" not in kinds  # aceito some
        assert not quiet["open"] and not any(quiet["changes"].values())
        assert data["totals"]["open"] == 1 and data["totals"]["complete"] == 2
        title, text = digest.render(data)
        assert title == "Resumo diário · 1 problema(s) aberto(s)"
        assert "Sem novidade: quiet.dev" in text and "[crítico] takeover blog.acme.com" in text
        assert "acme.com|A" not in text
    finally:
        s.close()
        os.remove(db)


def test_build_marca_alvo_sem_scan_recente():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    cfg = Config(targets=["parado.com"], db_path=db, interval_seconds=3600)
    try:
        data = digest.build(cfg, s, time.time() - 86400)
        assert data["targets"][0]["stale"] is True and not digest.is_quiet(data)
        assert "ATENÇÃO: sem scan recente" in digest.render(data)[1]
    finally:
        s.close()
        os.remove(db)


def test_render_nada_mudou():
    data = {"schedule": "weekly", "period_start": "2026-10-19T09:00", "period_end": "2026-10-26T09:00",
            "targets": [{"target": "a.com", "changes": {"added": 0, "changed": 0, "removed": 0},
                         "open": 0, "open_by_severity": {}, "sla_breached": 0, "new": [],
                         "resolved": [], "treated": 0, "highlights": [], "last_scan_at": None,
                         "stale": False, "partial": False, "degraded": []}],
            "totals": {"targets": 1, "open": 0, "open_by_severity": {}, "sla_breached": 0,
                       "changes": {"added": 0, "changed": 0, "removed": 0}, "complete": 1}}
    title, text = digest.render(data)
    assert title == "Resumo semanal · nada mudou" and "Sem novidade: a.com" in text


# ── envio ────────────────────────────────────────────────────────────────────
class _Canal:
    def __init__(self, name, ok=True):
        self.name, self.ok, self.got = name, ok, []

    async def send_digest(self, title, text, data):
        self.got.append((title, text, data))
        return NotificationResult(self.name, ok=self.ok, attempts=1)


def test_send_marca_so_quando_algum_canal_entrega_e_filtra_canais():
    db = tempfile.mktemp(suffix=".db")
    s = _populated(db)
    try:
        cfg = _cfg(db, channels=["telegram"])
        tg, mail = _Canal("telegram", ok=False), _Canal("email")
        res = asyncio.run(digest.send(cfg, s, NotificationManager([tg, mail]), time.time() - 3600))
        assert [r.channel for r in res] == ["telegram"] and not mail.got   # só o escolhido
        assert s.get_meta("digest.last_sent_at") is None                  # falhou: tenta de novo
        tg.ok = True
        asyncio.run(digest.send(cfg, s, NotificationManager([tg, mail]), time.time() - 3600))
        assert s.get_meta("digest.last_sent_at") is not None
        assert tg.got[-1][2]["totals"]["open"] == 1                        # dados estruturados juntos
    finally:
        s.close()
        os.remove(db)


def test_send_if_quiet_false_pula_e_marca():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("quiet.dev", [])
    s.update_health("quiet.dev", error_count=0, partial=False, duration_ms=5)
    try:
        cfg = Config(targets=["quiet.dev"], db_path=db,
                     digest=DigestConfig(enabled=True, send_if_quiet=False))
        canal = _Canal("email")
        assert asyncio.run(digest.send(cfg, s, NotificationManager([canal]), time.time() - 3600)) is None
        assert not canal.got and s.get_meta("digest.last_sent_at") is not None
    finally:
        s.close()
        os.remove(db)


def test_canais_formatam_o_resumo(monkeypatch):
    sent = {}

    async def tg_send(self, text):
        sent["tg"] = text
        return NotificationResult("telegram", ok=True, attempts=1)

    async def dc_msgs(self, msgs):
        sent["dc"] = msgs
        return NotificationResult("discord", ok=True, attempts=1)

    async def wh_post(self, payload):
        sent["wh"] = payload
        return NotificationResult("webhook", ok=True, attempts=1)

    async def em_send(self, subject, body):
        sent["em"] = (subject, body)
        return NotificationResult("email", ok=True, attempts=1)

    monkeypatch.setattr(TelegramNotifier, "send", tg_send)
    monkeypatch.setattr(DiscordNotifier, "_post_messages", dc_msgs)
    monkeypatch.setattr(WebhookNotifier, "_post", wh_post)
    monkeypatch.setattr(EmailNotifier, "_send", em_send)
    text = "acme.com\n  novo: WILDCARD · *.acme.com — <x>\n" + "linha `com crase`\n" * 300
    chans = [TelegramNotifier("t", "c"), DiscordNotifier("https://d"), WebhookNotifier("https://w"),
             EmailNotifier("smtp", 587, "", "", "a@x", ["b@x"])]
    asyncio.run(NotificationManager(chans).digest("Resumo diário · ok", text, {"totals": {"open": 0}}))
    assert "&lt;x&gt;" in sent["tg"] and "<b>Padmé · Resumo diário · ok</b>" in sent["tg"]
    assert len(sent["dc"]) > 1 and all(m.count("```") == 2 for m in sent["dc"])   # cerca por pedaço
    assert all(len(m) <= 2000 for m in sent["dc"]) and "`com crase`" not in "".join(sent["dc"])
    assert sent["wh"]["type"] == "digest" and sent["wh"]["digest"] == {"totals": {"open": 0}}
    assert sent["em"][0] == "[Padmé] Resumo diário · ok"


# ── config / CLI / monitor ───────────────────────────────────────────────────
def test_config_digest(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: [a.com]\ndigest:\n  enabled: true\n  schedule: weekly\n"
                 "  weekday: Friday\n  hour: 18\n  channels: telegram\n", encoding="utf-8")
    d = Config.load(p).digest
    assert (d.enabled, d.schedule, d.weekday, d.hour, d.channels) == (True, "weekly", "fri", 18, ["telegram"])
    for bad, msg in (("schedule: hourly", "daily ou weekly"), ("hour: 24", "0..23"),
                     ("weekday: xyz", "weekday"), ("channels: [slack]", "canal desconhecido")):
        p.write_text(f"targets: [a.com]\ndigest:\n  {bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match=msg):
            Config.load(p)


def test_cli_digest_print(tmp_path, capsys):
    db = str(tmp_path / "p.db")
    _populated(db).close()
    cfg = tmp_path / "c.yaml"
    cfg.write_text(f"targets: [acme.com, quiet.dev]\ndb_path: {db}\n", encoding="utf-8")
    assert main(["-c", str(cfg), "digest", "--print", "--hours", "2"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Resumo diário · 1 problema(s) aberto(s)") and "Sem novidade: quiet.dev" in out
    s = Storage(db)
    assert s.get_meta("digest.last_sent_at") is None        # --print não marca envio
    s.close()
    assert main(["-c", str(cfg), "digest"]) == 1           # sem canal: orienta a usar --print
    assert "--print" in capsys.readouterr().err


def test_monitor_acorda_no_horario_do_resumo(monkeypatch):
    chamadas, dormidas = [], []

    async def fake_maybe(cfg, storage, notifier):
        chamadas.append(1)

    monkeypatch.setattr(scheduler.digest, "maybe_send", fake_maybe)
    monkeypatch.setattr(scheduler.digest, "seconds_until_next", lambda cfg: 100.0)

    class Relogio:
        t = 0.0

        def time(self):
            return self.t

    rel = Relogio()

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "time", rel.time)

        async def sleep_and_advance(sec):
            dormidas.append(sec)
            rel.t += sec
        monkeypatch.setattr(scheduler.asyncio, "sleep", sleep_and_advance)
        await scheduler._sleep_until_next_scan(Config(targets=["a.com"]), None, None, 3600)

    asyncio.run(run())
    assert dormidas[0] == 101.0 and chamadas == [1] * (len(dormidas) - 1)   # acorda p/ o resumo
    assert abs(sum(dormidas) - 3600) < 1e-6                                  # e volta a dormir até o scan


def test_canal_inexistente_marca_e_nao_repete_o_aviso():
    db = tempfile.mktemp(suffix=".db")
    s = _populated(db)
    try:
        cfg = _cfg(db, channels=["discord"])                       # discord não está ativo
        res = asyncio.run(digest.send(cfg, s, NotificationManager([_Canal("email")]),
                                      time.time() - 3600))
        assert res == [] and s.get_meta("digest.last_sent_at") is not None
    finally:
        s.close()
        os.remove(db)
