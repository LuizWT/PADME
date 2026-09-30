"""Refatorações da revisão: config, --level, scan pelo caminho do monitor e
mapa de portas único."""

import argparse
import asyncio
import os
import tempfile

from padme import scheduler
from padme.cli import _cmd_scan, _override_levels
from padme.collectors.ports import fingerprint
from padme.config import Config, _expand, _unknown_keys
from padme.models import Kind, Record, ScanResult
from padme.portmap import DATA_PORTS, HIGH_RISK_PORTS, SERVICE_BY_PORT
from padme.risk import Level, assess
from padme.storage import Storage


def test_expand_em_qualquer_ponto(monkeypatch):
    monkeypatch.setenv("PADME_TK", "abc")
    assert _expand("Bearer ${PADME_TK}") == "Bearer abc"
    assert _expand("${PADME_TK}") == "abc"
    assert _expand("x-${NAO_EXISTE}-y") == "x--y"
    assert _expand("sem variavel") == "sem variavel"


def test_chave_desconhecida_vira_aviso_com_sugestao():
    raw = {"targets": ["a.com"], "colectors": {}, "collectors": {"port": True},
           "email": {"from": "x@a.com", "form": "y"},
           "context": {"assets": [{"match": "a.com", "criticalty": "high"}]}}
    w = "\n".join(_unknown_keys(raw))
    assert "'colectors' (quis dizer 'collectors'?)" in w
    assert "'collectors.port' (quis dizer 'ports'?)" in w
    assert "'email.form'" in w and "'email.from'" not in w      # `from` é o nome do YAML
    assert "'context.assets[0].criticalty' (quis dizer 'criticality'?)" in w


def test_config_valida_sem_avisos(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("targets: [a.com]\nwebhook:\n  secret: x\nemail:\n  from: a@b.c\n")
    assert Config.load(cfg_file).warnings == []


def test_level_da_cli_vale_para_todos_os_canais():
    cfg = Config(targets=["a.com"])
    _override_levels(cfg, "critical")
    assert {cfg.telegram.level, cfg.discord.level, cfg.webhook.level, cfg.email.level} == {"critical"}


def test_scan_usa_o_caminho_do_monitor(monkeypatch, capsys):
    """`padme scan` passa por scheduler.scan_one — mesma saúde, mesmo flapping,
    mesma notificação (e agora a fila de reenvio) que o monitor."""
    db = tempfile.mktemp(suffix=".db")
    chamadas = []
    real = scheduler.scan_one

    async def espiao(cfg, engine, storage, notifier, target):
        chamadas.append(target)
        return await real(cfg, engine, storage, notifier, target)

    async def fake_scan(self, target):
        r = ScanResult(target=target)
        r.records.append(Record(Kind.SUBDOMAIN, f"api.{target}", "live"))
        return r

    monkeypatch.setattr(scheduler, "scan_one", espiao)
    monkeypatch.setattr("padme.engine.Engine.scan_target", fake_scan)
    cfg = Config(targets=["a.com"], db_path=db, scope_confirmed=True)
    try:
        args = argparse.Namespace(level=None, notify=False)
        assert asyncio.run(_cmd_scan(cfg, args)) == 0
        assert chamadas == ["a.com"]
        assert "baseline gravado: 1 itens" in capsys.readouterr().out
        s = Storage(db)
        assert s.target_meta("a.com")["last_duration_ms"] is not None   # saúde gravada
        s.close()
    finally:
        os.remove(db)


def test_mapa_de_portas_unico():
    assert HIGH_RISK_PORTS >= DATA_PORTS
    assert all(p in SERVICE_BY_PORT for p in HIGH_RISK_PORTS)   # toda porta de risco tem nome
    assert fingerprint(5985, "")["service"] == "winrm"          # o collector usa a mesma tabela
    from padme.models import Event, EventType
    e = Event("a.com", EventType.ADDED, Kind.PORT, "a.com:5985", None, "open", metadata={"port": 5985})
    assert assess(e).level == Level.CRITICAL                     # e o risco também
