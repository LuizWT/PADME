"""Item 7: alerta grave não entregue não se perde em silêncio.

Se um canal falha, os eventos HIGH/CRITICAL que ele deveria entregar entram numa
fila no banco e são reenviados a esse canal no ciclo seguinte (e após reinício).
Desiste depois de N tentativas ou 24h, com log de erro."""

import asyncio
import logging
import os
import tempfile

import pytest

from padme import scheduler
from padme.config import Config
from padme.levels import Level
from padme.models import Kind, Record, ScanResult
from padme.notify import NotificationManager, NotificationResult
from padme.storage import Storage


class _Canal:
    def __init__(self, name, level=Level.DEBUG, falha=False):
        self.name, self.level, self.falha = name, level, falha
        self.recebidos: list = []

    @property
    def configured(self):
        return True

    async def notify_events(self, target, events):
        if self.falha:
            return NotificationResult(self.name, ok=False, attempts=3, error="HTTP 502")
        self.recebidos.append(list(events))
        return NotificationResult(self.name, ok=True, attempts=1, status=200)

    async def announce(self, msg):
        return NotificationResult(self.name, ok=True, attempts=1)


@pytest.fixture
def storage():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [])  # baseline
    yield s
    s.close()
    os.remove(db)


def _eventos(s):
    """Um takeover (CRITICAL) e um registro DNS (DEBUG) novos."""
    return s.apply_scan("x.com", [
        Record(Kind.TAKEOVER, "blog.x.com", "GitHub Pages | x.github.io | NXDOMAIN",
               metadata={"cname": "x.github.io", "reason": "CNAME dangling (NXDOMAIN)"}),
        Record(Kind.DNS, "x.com|A|1.2.3.4", "1.2.3.4"),
    ])


def test_so_o_canal_que_falhou_e_so_o_grave_entram_na_fila(storage):
    evs = _eventos(storage)
    ruim, bom = _Canal("telegram", falha=True), _Canal("webhook")
    res = [NotificationResult("telegram", ok=False, attempts=3), NotificationResult("webhook", ok=True, attempts=1)]
    assert scheduler.queue_failed(storage, [ruim, bom], res, "x.com", evs) == 1
    pend = storage.pending_notifications("telegram")
    assert [p["event_id"] for p in pend] == [e.event_id for e in evs if e.kind == Kind.TAKEOVER]
    assert storage.pending_notifications("webhook") == []


def test_canal_com_nivel_alto_so_enfileira_o_que_ele_mandaria(storage):
    evs = _eventos(storage)
    canal = _Canal("email", level=Level.CRITICAL, falha=True)
    res = [NotificationResult("email", ok=False, attempts=3)]
    assert scheduler.queue_failed(storage, [canal], res, "x.com", evs) == 1   # só o takeover


def test_reenvio_entrega_e_limpa_a_fila(storage):
    evs = _eventos(storage)
    canal = _Canal("telegram", falha=True)
    scheduler.queue_failed(storage, [canal], [NotificationResult("telegram", ok=False)], "x.com", evs)
    canal.falha = False                                   # canal voltou
    asyncio.run(scheduler.retry_pending(storage, NotificationManager([canal])))
    assert [[e.kind for e in lote] for lote in canal.recebidos] == [[Kind.TAKEOVER]]
    assert storage.pending_notifications("telegram") == []


def test_reenvio_que_falha_conta_tentativa_e_desiste_com_log(storage, caplog):
    evs = _eventos(storage)
    canal = _Canal("telegram", falha=True)
    mgr = NotificationManager([canal])
    scheduler.queue_failed(storage, [canal], [NotificationResult("telegram", ok=False)], "x.com", evs)
    for _ in range(scheduler._RETRY_MAX_ATTEMPTS):
        asyncio.run(scheduler.retry_pending(storage, mgr))
    assert storage.pending_notifications("telegram")[0]["attempts"] == scheduler._RETRY_MAX_ATTEMPTS
    with caplog.at_level(logging.ERROR, logger="padme"):
        asyncio.run(scheduler.retry_pending(storage, mgr))
    assert storage.pending_notifications("telegram") == []
    assert "DESISTINDO" in caplog.text                  # nunca some sem aviso


def test_pendencia_velha_expira(storage, caplog):
    evs = _eventos(storage)
    canal = _Canal("telegram")
    scheduler.queue_failed(storage, [canal], [NotificationResult("telegram", ok=False)], "x.com", evs)
    storage._conn.execute("UPDATE pending_notifications SET created_at = created_at - ?",
                          (scheduler._RETRY_MAX_AGE + 60,))
    with caplog.at_level(logging.ERROR, logger="padme"):
        asyncio.run(scheduler.retry_pending(storage, NotificationManager([canal])))
    assert canal.recebidos == [] and storage.pending_notifications("telegram") == []
    assert "DESISTINDO" in caplog.text


def test_evento_apagado_pela_retencao_sai_da_fila(storage):
    evs = _eventos(storage)
    canal = _Canal("telegram")
    scheduler.queue_failed(storage, [canal], [NotificationResult("telegram", ok=False)], "x.com", evs)
    storage._conn.execute("DELETE FROM events")
    asyncio.run(scheduler.retry_pending(storage, NotificationManager([canal])))
    assert canal.recebidos == [] and storage.pending_notifications("telegram") == []


def test_run_cycle_enfileira_quando_o_canal_falha(storage):
    evs = _eventos(storage)

    class _Engine:
        async def scan_target(self, target):
            return ScanResult(target=target)

        def apply(self, result):
            return evs

    canal = _Canal("telegram", falha=True)
    cfg = Config(targets=["x.com"], db_path=":memory:")
    asyncio.run(scheduler._run_cycle(cfg, _Engine(), storage, NotificationManager([canal]), 1))
    assert len(storage.pending_notifications("telegram")) == 1


def test_doctor_mostra_pendencias(capsys):
    from padme.cli import _cmd_doctor
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.queue_notifications("telegram", "x.com", ["e1", "e2"])
    s.close()
    try:
        asyncio.run(_cmd_doctor(Config(targets=["x.com"], db_path=db), None))
        assert "aguardando reenvio: telegram=2" in capsys.readouterr().out
    finally:
        os.remove(db)
