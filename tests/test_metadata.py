"""§23 — metadata estruturada no Record/Event (persistência, webhook, migração)."""

import asyncio
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

from padme.collectors import tls
from padme.models import Event, EventType, Kind, Record
from padme.notify.webhook import event_to_dict
from padme.storage import Storage


def test_tls_gera_metadata(monkeypatch):
    na = datetime.now(timezone.utc) + timedelta(days=90)

    def fake(host, port, timeout):
        return {"fp": "abc123", "issuer": "Let's Encrypt", "not_after": na}

    monkeypatch.setattr(tls, "_blocking_cert", fake)
    cr = asyncio.run(tls.collect_host("x.com", 5))
    m = next(r.metadata for r in cr.records if r.kind == Kind.TLS)
    assert m["issuer"] == "Let's Encrypt"
    assert m["fingerprint"] == "abc123"
    assert m["expires_at"]  # ISO não vazio


def test_metadata_round_trip_state_e_evento():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [])  # baseline
    evs = s.apply_scan(
        "x.com",
        [Record(Kind.TLS, "x.com:443", "issuer=LE | fp=z",
                metadata={"issuer": "LE", "fingerprint": "z"})],
        observed_scopes={("tls", "x.com")},
    )
    # evento added carrega o metadata
    assert evs[0].metadata == {"issuer": "LE", "fingerprint": "z"}
    # persistido no state (all_state devolve dict)
    row = next(r for r in s.all_state(["x.com"]) if r["kind"] == "tls")
    assert row["metadata"] == {"issuer": "LE", "fingerprint": "z"}
    # recarregado em recent_events
    e = s.recent_events("x.com")[0]
    assert e.metadata["issuer"] == "LE"
    s.close(); os.remove(db)


def test_sem_metadata_fica_vazio():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [])
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:22", "open")],
                 observed_scopes={("port", "x.com")})
    assert s.recent_events("x.com")[0].metadata == {}
    assert next(r for r in s.all_state(["x.com"]))["metadata"] == {}
    s.close(); os.remove(db)


def test_webhook_inclui_metadata():
    e = Event("x.com", EventType.ADDED, Kind.TLS, "x.com:443", None, "v",
              metadata={"issuer": "LE", "expires_at": "2026-10-01T00:00:00+00:00"})
    d = event_to_dict(e)
    assert d["metadata"]["issuer"] == "LE"


def test_migracao_v3_para_v4_metadata():
    db = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE state (target TEXT, kind TEXT, key TEXT, value TEXT,"
        " first_seen REAL, last_seen REAL, PRIMARY KEY(target,kind,key));"
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,"
        " ts REAL, event_type TEXT, kind TEXT, key TEXT, old_value TEXT, new_value TEXT);"
        "CREATE TABLE targets (target TEXT PRIMARY KEY, baseline_initialized INTEGER);"
    )
    con.execute("PRAGMA user_version = 3")
    con.commit(); con.close()
    s = Storage(db)
    assert s._has_column("state", "metadata")
    assert s._has_column("events", "metadata")
    s.close(); os.remove(db)
