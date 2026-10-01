"""Fase 4 — operação: saúde da coleta, retenção, integridade, doctor, lock."""

import asyncio
import os
import tempfile
import time

from padme.models import Kind, Record
from padme.storage import Storage


def _storage():
    db = tempfile.mktemp(suffix=".db")
    return Storage(db), db


# ── §50 saúde da coleta ─────────────────────────────────────────────────────
def test_update_health_limpo_e_parcial():
    s, db = _storage()
    s.apply_scan("x.com", [])  # cria a linha do alvo
    s.update_health("x.com", error_count=0, partial=False, duration_ms=42)
    m = s.target_meta("x.com")
    assert m["last_error_count"] == 0 and m["last_partial"] == 0 and m["last_duration_ms"] == 42
    ok1 = m["last_success_at"]
    assert ok1 is not None

    time.sleep(0.01)
    s.update_health("x.com", error_count=2, partial=True, duration_ms=99)
    m2 = s.target_meta("x.com")
    assert m2["last_error_count"] == 2 and m2["last_partial"] == 1
    assert m2["last_success_at"] == ok1          # sucesso NÃO avança em coleta parcial
    assert m2["last_scan_at"] >= m["last_scan_at"]  # mas o último scan sim
    s.close(); os.remove(db)


# ── §29 retenção do histórico ───────────────────────────────────────────────
def test_prune_events():
    s, db = _storage()
    s.apply_scan("x.com", [])  # baseline
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:1", "open")],
                 observed_scopes={("port", "x.com")})  # 1 evento hoje
    old_ts = time.time() - 40 * 86400
    s._conn.execute(
        "INSERT INTO events (target, ts, event_type, kind, key) VALUES (?,?,?,?,?)",
        ("x.com", old_ts, "added", "port", "x.com:2"))
    s._conn.commit()

    assert s.prune_events(0) == 0            # 0 = mantém tudo
    assert s.prune_events(30) == 1           # remove só o antigo
    assert len(s.recent_events("x.com")) == 1  # o de hoje fica
    # state intacto
    assert len(s.all_state(["x.com"])) == 1
    s.close(); os.remove(db)


# ── §30 integridade + contagens ─────────────────────────────────────────────
def test_integrity_e_counts():
    s, db = _storage()
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:1", "open")])  # baseline
    assert s.integrity_check() == "ok"
    c = s.counts()
    assert c["targets"] >= 1 and c["state"] == 1
    s.close(); os.remove(db)


# ── §30 comando doctor ──────────────────────────────────────────────────────
def test_doctor(capsys, monkeypatch):
    from padme.cli import _cmd_doctor
    from padme.config import Config

    async def _no_net(cfg, timeout=5.0):   # sondas de rede não tocam a rede nos testes
        return []
    monkeypatch.setattr("padme.cli.netcheck.run", _no_net)
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:1", "open")])
    s.update_health("x.com", error_count=0, partial=False, duration_ms=10)
    s.close()
    cfg = Config(targets=["x.com"], db_path=db)
    rc = asyncio.run(_cmd_doctor(cfg, None))
    out = capsys.readouterr().out
    os.remove(db)
    assert rc == 0
    assert "integridade" in out and "x.com" in out and "baseline=sim" in out


# ── §33/§35/§36 avisos de config (via doctor) ───────────────────────────────
def test_config_warnings():
    import pytest

    from padme.cli import _config_warnings
    from padme.config import Config, TelegramConfig, _validate

    # limite numérico é erro de carregamento (config._validate), não aviso do doctor
    with pytest.raises(ValueError, match="interval_seconds"):
        _validate(Config(targets=["x.com"], interval_seconds=0))
    cfg = Config(targets=["x.com"])
    cfg.telegram = TelegramConfig(enabled=True, bot_token="SEU_BOT_TOKEN_AQUI", chat_id="")
    w = _config_warnings(cfg)
    assert any("telegram" in x for x in w)


# ── §52 aviso de exposição do painel ────────────────────────────────────────
def test_webpanel_banner_exposto():
    from padme.config import Config
    from padme.webpanel import _render

    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:1", "open")])
    s.close()
    cfg = Config(targets=["x.com"], db_path=db)
    exposto = _render(cfg, exposed=True)
    local = _render(cfg, exposed=False)
    os.remove(db)
    assert "SEM autenticação" in exposto
    assert "SEM autenticação" not in local


# ── §49 lock multiplataforma ────────────────────────────────────────────────
def test_singleton_tem_mecanismo():
    from padme import singleton
    assert singleton._MODE in ("fcntl", "msvcrt")   # no Linux/macOS: fcntl


# ── parser expõe doctor ─────────────────────────────────────────────────────
def test_parser_tem_doctor():
    from padme.cli import build_parser
    args = build_parser().parse_args(["doctor"])
    assert hasattr(args, "func")
