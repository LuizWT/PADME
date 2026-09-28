"""Saúde por collector (§7): ok / partial / error, persistida em targets (JSON)."""

import os
import sqlite3
import tempfile

from padme.engine import summarize_health
from padme.models import ScanResult
from padme.storage import Storage


def test_summarize_health_status():
    r = ScanResult(target="x.com")
    r.mark_collector("dns", True)
    r.mark_collector("http", True)
    r.mark_collector("http", False)      # 1 host falhou -> partial
    r.mark_collector("ports", False)     # só falha -> error
    h = summarize_health(r)
    assert h["dns"]["status"] == "ok"
    assert h["http"]["status"] == "partial" and h["http"]["ok"] == 1 and h["http"]["fail"] == 1
    assert h["ports"]["status"] == "error"


def test_health_persistida_e_decodificada():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [])  # cria o alvo (baseline)
    s.update_health("x.com", error_count=1, partial=True, duration_ms=10,
                    collectors={"dns": {"status": "ok", "ok": 1, "fail": 0},
                                "ports": {"status": "error", "ok": 0, "fail": 1}})
    m = s.target_meta("x.com")
    s.close(); os.remove(db)
    assert isinstance(m["collectors_health"], dict)
    assert m["collectors_health"]["ports"]["status"] == "error"


def test_migracao_v4_para_v5_collectors_health():
    db = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE state (target TEXT, kind TEXT, key TEXT, value TEXT,"
        " first_seen REAL, last_seen REAL, metadata TEXT, PRIMARY KEY(target,kind,key));"
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, ts REAL,"
        " event_type TEXT, kind TEXT, key TEXT, old_value TEXT, new_value TEXT, metadata TEXT);"
        "CREATE TABLE targets (target TEXT PRIMARY KEY, baseline_initialized INTEGER);"
    )
    con.execute("PRAGMA user_version = 4")
    con.commit(); con.close()
    s = Storage(db)
    assert s._has_column("targets", "collectors_health")
    s.close(); os.remove(db)
