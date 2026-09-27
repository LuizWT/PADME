"""Amortecimento de flapping: chave que oscila para de ser notificada."""

import os
import tempfile
import time

from padme.alerts import damp_flapping
from padme.models import Event, EventType, Kind
from padme.storage import Storage


def _ev(kind, key):
    return Event("x.com", EventType.ADDED, kind, key)


def _insert(s, kind, key, ts, n):
    for _ in range(n):
        s._conn.execute(
            "INSERT INTO events (target, ts, event_type, kind, key) VALUES (?,?,?,?,?)",
            ("x.com", ts, "added", kind, key))
    s._conn.commit()


def test_flap_suprime_chave_que_oscila():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    now = time.time()
    _insert(s, "port", "x.com:22", now - 60, 4)      # chave flapping (4 na janela)
    _insert(s, "subdomain", "api.x.com", now - 60, 1)  # chave estável
    to_notify, flapped = damp_flapping(
        s, "x.com", [_ev(Kind.PORT, "x.com:22"), _ev(Kind.SUBDOMAIN, "api.x.com")],
        threshold=4, window_minutes=60)
    s.close(); os.remove(db)
    assert flapped == 1
    assert [e.key for e in to_notify] == ["api.x.com"]


def test_flap_desligado_por_threshold_zero():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    ev = [_ev(Kind.PORT, "x.com:22")]
    to_notify, flapped = damp_flapping(s, "x.com", ev, threshold=0, window_minutes=60)
    s.close(); os.remove(db)
    assert flapped == 0 and to_notify == ev


def test_flap_fora_da_janela_nao_suprime():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    _insert(s, "port", "x.com:22", time.time() - 3 * 3600, 6)  # 3h atrás, fora de 60min
    to_notify, flapped = damp_flapping(
        s, "x.com", [_ev(Kind.PORT, "x.com:22")], threshold=4, window_minutes=60)
    s.close(); os.remove(db)
    assert flapped == 0 and len(to_notify) == 1
