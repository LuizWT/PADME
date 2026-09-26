"""P0.3 / P0.5 / P0.7 — baseline, alvo conhecido e erro de coleta != removido."""

import os
import sqlite3
import tempfile

from padme.models import Kind, Record
from padme.storage import Storage


def _storage():
    db = tempfile.mktemp(suffix=".db")
    return Storage(db), db


# ── P0.3 baseline ──────────────────────────────────────────────────────────
def test_baseline_nao_gera_eventos():
    s, db = _storage()
    evs = s.apply_scan("x.com", [
        Record(Kind.SUBDOMAIN, "a.x.com", "live"),
        Record(Kind.PORT, "x.com:443", "open"),
    ])
    assert evs == []                          # 1º scan = baseline, sem eventos
    assert s.recent_events("x.com") == []     # histórico limpo
    assert len(s.all_state(["x.com"])) == 2   # mas o estado foi gravado
    s.close(); os.remove(db)


def test_segundo_scan_gera_added():
    s, db = _storage()
    s.apply_scan("x.com", [Record(Kind.SUBDOMAIN, "a.x.com", "live")])  # baseline
    evs = s.apply_scan("x.com", [
        Record(Kind.SUBDOMAIN, "a.x.com", "live"),
        Record(Kind.SUBDOMAIN, "b.x.com", "live"),
    ])
    assert [e.event_type.value for e in evs] == ["added"]
    assert evs[0].key == "b.x.com"
    s.close(); os.remove(db)


# ── P0.7 alvo conhecido mesmo com state vazio ────────────────────────────────
def test_alvo_conhecido_com_state_vazio():
    s, db = _storage()
    evs = s.apply_scan("x.com", [])           # scan válido, zero records
    assert evs == []
    assert s.is_known_target("x.com") is True  # conhecido, apesar do state vazio
    assert s.all_state(["x.com"]) == []
    # o próximo achado é ADDED real (não um novo baseline)
    evs2 = s.apply_scan("x.com", [Record(Kind.PORT, "x.com:22", "open")],
                        observed_scopes={("port", "x.com")})
    assert [e.event_type.value for e in evs2] == ["added"]
    s.close(); os.remove(db)


# ── P0.5 erro de coleta não vira REMOVED ────────────────────────────────────
def test_escopo_nao_observado_preserva_estado():
    s, db = _storage()
    s.apply_scan("x.com", [])  # baseline
    # scan 2: DNS observado, grava 1 registro
    s.apply_scan("x.com", [Record(Kind.DNS, "x.com|A|1.2.3.4", "1.2.3.4")],
                 observed_scopes={("dns", "x.com")})
    assert len(s.all_state(["x.com"])) == 1

    # scan 3: coleta de DNS FALHOU (escopo não observado) -> preserva, sem REMOVED
    evs = s.apply_scan("x.com", [], observed_scopes=set())
    assert evs == []
    assert len(s.all_state(["x.com"])) == 1   # registro anterior preservado

    # scan 4: DNS observado e o registro sumiu de fato -> REMOVED real
    evs = s.apply_scan("x.com", [], observed_scopes={("dns", "x.com")})
    assert [e.event_type.value for e in evs] == ["removed"]
    assert s.all_state(["x.com"]) == []
    s.close(); os.remove(db)


def test_added_em_escopo_falho_ainda_registra():
    """Um serviço observado presente gera ADDED mesmo que outro escopo falhe."""
    s, db = _storage()
    s.apply_scan("x.com", [])  # baseline
    evs = s.apply_scan(
        "x.com",
        [Record(Kind.HTTP, "https://x.com", "200 | nginx | ")],
        observed_scopes={("http", "x.com")},  # DNS não observado, HTTP sim
    )
    assert [e.event_type.value for e in evs] == ["added"]
    s.close(); os.remove(db)


# ── P0.3/P0.7 via migração de banco antigo (sem tabela targets) ─────────────
def test_migracao_backfill_nao_rebaselina():
    db = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE state (target TEXT, kind TEXT, key TEXT, value TEXT,"
        " first_seen REAL, last_seen REAL, PRIMARY KEY(target,kind,key));"
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,"
        " ts REAL, event_type TEXT, kind TEXT, key TEXT, old_value TEXT, new_value TEXT);"
    )
    con.execute("INSERT INTO state VALUES ('x.com','subdomain','a.x.com','live',1.0,1.0)")
    con.commit(); con.close()

    s = Storage(db)  # deve migrar: cria targets + backfill baseline_initialized=1
    assert s.is_known_target("x.com") is True         # não re-baseliniza
    assert s._conn.execute("PRAGMA user_version").fetchone()[0] == 3
    # como já é conhecido, um sumiço observado gera REMOVED (não vira baseline)
    evs = s.apply_scan("x.com", [], observed_scopes={("subdomain", "x.com")})
    assert [e.event_type.value for e in evs] == ["removed"]
    s.close(); os.remove(db)
