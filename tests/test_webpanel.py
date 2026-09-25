"""Teste do painel web read-only."""

import os
import tempfile

from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.webpanel import _render


def test_render():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("alvo.com", [
        Record(Kind.PORT, "alvo.com:443", "open"),
        Record(Kind.SUBDOMAIN, "api.alvo.com", ""),
    ])
    s.close()
    cfg = Config(targets=["alvo.com"], db_path=db)
    out = _render(cfg)
    os.remove(db)
    assert "alvo.com" in out
    assert "PORT" in out and "alvo.com:443" in out
    assert "<html" in out.lower()
