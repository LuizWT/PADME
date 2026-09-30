"""Fase 3 — arquitetura: IDs/UTC, migração v2, manager, formatter único."""

import asyncio
import os
import sqlite3
import tempfile

from padme.models import Event, EventType, Kind, Record
from padme.notify import NotificationManager, NotificationResult
from padme.risk import Level
from padme.storage import Storage


def _storage():
    db = tempfile.mktemp(suffix=".db")
    return Storage(db), db


# ── §24/§27 event_id + scan_id + detected_at (UTC) ──────────────────────────
def test_eventos_tem_ids_e_utc():
    s, db = _storage()
    s.apply_scan("x.com", [])  # baseline
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:443", "open")],
                 observed_scopes={("port", "x.com")})
    evs = s.recent_events("x.com")
    s.close(); os.remove(db)
    assert len(evs) == 1
    assert evs[0].event_id and evs[0].scan_id
    assert evs[0].detected_at.endswith("+00:00")  # ISO-8601 em UTC


def test_mesmo_scan_compartilha_scan_id():
    s, db = _storage()
    s.apply_scan("x.com", [])  # baseline
    s.apply_scan("x.com", [Record(Kind.PORT, "x.com:1", "open"),
                           Record(Kind.PORT, "x.com:2", "open")],
                 observed_scopes={("port", "x.com")})
    evs = s.recent_events("x.com")
    s.close(); os.remove(db)
    assert len({e.scan_id for e in evs}) == 1     # mesmo scan
    assert len({e.event_id for e in evs}) == 2    # ids de evento únicos


# ── §28 migração incremental v1 -> v2 ───────────────────────────────────────
def test_migracao_v1_para_v2():
    db = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE state (target TEXT, kind TEXT, key TEXT, value TEXT,"
        " first_seen REAL, last_seen REAL, PRIMARY KEY(target,kind,key));"
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,"
        " ts REAL, event_type TEXT, kind TEXT, key TEXT, old_value TEXT, new_value TEXT);"
        "CREATE TABLE targets (target TEXT PRIMARY KEY, first_scan_at REAL,"
        " last_scan_at REAL, last_success_at REAL, baseline_initialized INTEGER NOT NULL DEFAULT 0);"
    )
    con.execute("PRAGMA user_version = 1")
    con.commit(); con.close()

    s = Storage(db)
    assert s._has_column("events", "event_id")
    assert s._has_column("events", "scan_id")
    from padme import storage as _stg
    assert s._conn.execute("PRAGMA user_version").fetchone()[0] == _stg._SCHEMA_VERSION
    s.close(); os.remove(db)


# ── §2/§46 NotificationManager ──────────────────────────────────────────────
class _Fake:
    def __init__(self, name, level):
        self.name = name
        self.level = level
        self.announced = None

    @property
    def configured(self):
        return True

    async def notify_events(self, target, events):
        return NotificationResult(self.name, ok=True, attempts=1, status=204)

    async def announce(self, msg):
        self.announced = msg
        return NotificationResult(self.name, ok=True, attempts=1)


def _events():
    return [Event("x.com", EventType.ADDED, Kind.TAKEOVER, "a.x.com"),
            Event("x.com", EventType.ADDED, Kind.DNS, "x.com|A|1", None, "1")]


def test_manager_dispatch_e_announce():
    tg, dc = _Fake("telegram", Level.DEBUG), _Fake("discord", Level.DEBUG)
    m = NotificationManager([tg, dc])
    assert bool(m) is True
    res = asyncio.run(m.dispatch("x.com", _events()))
    assert {r.channel for r in res} == {"telegram", "discord"}
    ares = asyncio.run(m.announce("sentinela on"))
    assert all(r.ok for r in ares)
    assert tg.announced == "sentinela on" and dc.announced == "sentinela on"


def test_manager_vazio_e_falsy():
    assert bool(NotificationManager([])) is False


# ── §13 formatter é fonte única (sem acoplamento entre canais) ──────────────
def test_formatter_fonte_unica():
    from padme.notify import email, formatting, telegram, webhook
    assert telegram._DESC is formatting.DESC
    assert webhook._KIND_ORDER is formatting.KIND_ORDER
    assert email._MARK is formatting.MARK
