"""Operação: `padme health` (liveness p/ HEALTHCHECK/cron) e SIGTERM limpo."""

import asyncio
import os
import signal
import sqlite3
import time

from padme import scheduler
from padme.cli import main
from padme.config import Config
from padme.storage import Storage


def _cfg_file(tmp_path, interval=3600):
    p = tmp_path / "config.yaml"
    p.write_text(f"scope_confirmed: true\ninterval_seconds: {interval}\n"
                 "db_path: padme.db\ntargets:\n  - example.com\n")
    return str(p)


def _scanned(tmp_path, when):
    Storage(tmp_path / "padme.db").close()
    con = sqlite3.connect(tmp_path / "padme.db")
    con.execute("INSERT INTO targets (target, first_scan_at, last_scan_at, baseline_initialized)"
                " VALUES ('example.com', ?, ?, 1)", (when, when))
    con.commit()
    con.close()


def test_health_sem_banco_unhealthy(tmp_path, capsys):
    assert main(["-c", _cfg_file(tmp_path), "health"]) == 1
    assert "unhealthy" in capsys.readouterr().out
    assert not (tmp_path / "padme.db").exists()  # read-only: não cria o banco


def test_health_sem_scan_unhealthy(tmp_path, capsys):
    Storage(tmp_path / "padme.db").close()
    assert main(["-c", _cfg_file(tmp_path), "health"]) == 1
    assert "nenhum scan" in capsys.readouterr().out


def test_health_scan_recente_healthy(tmp_path, capsys):
    _scanned(tmp_path, time.time() - 60)
    assert main(["-c", _cfg_file(tmp_path), "health"]) == 0
    assert "healthy" in capsys.readouterr().out


def test_health_scan_atrasado_unhealthy(tmp_path):
    # padrão: 2*interval + 600 = 7800s
    _scanned(tmp_path, time.time() - 8000)
    assert main(["-c", _cfg_file(tmp_path), "health"]) == 1


def test_health_max_age_explicito(tmp_path):
    _scanned(tmp_path, time.time() - 120)
    cfg = _cfg_file(tmp_path)
    assert main(["-c", cfg, "health", "--max-age", "60"]) == 1
    assert main(["-c", cfg, "health", "--max-age", "300"]) == 0


def test_health_nao_exige_scope_confirmed(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("db_path: padme.db\ntargets:\n  - example.com\n")
    assert main(["-c", str(p), "health"]) == 1  # 1 (sem banco), não 3 (escopo)


def test_sigterm_encerra_monitor_limpo(tmp_path, monkeypatch):
    anuncios = []

    class FakeNotifier:
        name = "fake"
        level = "info"

        async def announce(self, text):
            anuncios.append(text)

    async def ciclo(*a, **k):
        return True

    monkeypatch.setattr(scheduler, "build_notifiers", lambda cfg: [FakeNotifier()])
    monkeypatch.setattr(scheduler, "_run_cycle", ciclo)
    monkeypatch.setattr(scheduler, "retry_pending", lambda *a: asyncio.sleep(0))
    cfg = Config.load(_cfg_file(tmp_path, interval=60))

    async def roda():
        asyncio.get_running_loop().call_later(0.2, os.kill, os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(scheduler.run_monitor(cfg), timeout=5)

    asyncio.run(roda())
    assert any("encerrado" in a for a in anuncios)
