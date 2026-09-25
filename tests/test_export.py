"""Testes do export de estado (JSON/CSV)."""

import json
import os
import tempfile

from padme.cli import _render_export
from padme.models import Kind, Record
from padme.storage import Storage


def _storage_with_data():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [
        Record(Kind.PORT, "alvo.com:443", "open"),
        Record(Kind.SUBDOMAIN, "api.alvo.com", ""),
    ])
    return s, db


def test_all_state():
    s, db = _storage_with_data()
    rows = s.all_state(["alvo.com"])
    s.close()
    os.remove(db)
    assert len(rows) == 2
    assert {r["kind"] for r in rows} == {"port", "subdomain"}
    assert "first_seen" in rows[0]


def test_export_json():
    s, db = _storage_with_data()
    rows = s.all_state()
    s.close()
    os.remove(db)
    data = json.loads(_render_export(rows, "json"))
    assert data[0]["target"] == "alvo.com"
    assert data[0]["first_seen"]  # ISO não vazio


def test_export_csv():
    s, db = _storage_with_data()
    rows = s.all_state()
    s.close()
    os.remove(db)
    csv_text = _render_export(rows, "csv")
    assert csv_text.splitlines()[0] == "target,kind,key,value,first_seen,last_seen"
    assert "alvo.com:443" in csv_text
