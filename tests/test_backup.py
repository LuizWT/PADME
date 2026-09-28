"""Teste do backup online do SQLite (§14.2)."""

import os
import sqlite3
import tempfile

from padme.models import Kind, Record
from padme.storage import Storage


def test_backup_consistente_e_integro():
    src = tempfile.mktemp(suffix=".db")
    dst = tempfile.mktemp(suffix=".db")
    s = Storage(src)
    s.apply_scan("a.com", [])  # baseline
    s.apply_scan("a.com", [
        Record(Kind.PORT, "a.com:443", "open"),
        Record(Kind.SUBDOMAIN, "x.a.com", "live"),
    ])
    esperado = s.counts()          # contagens da origem
    res = s.backup(dst)            # backup com a conexão viva (online)
    s.close()

    assert res["integrity"] == "ok"
    assert res["bytes"] > 0
    # o backup é um banco válido e carrega as MESMAS contagens
    b = Storage(dst)
    try:
        assert b.counts() == esperado
        assert b.integrity_check() == "ok"
    finally:
        b.close()
    os.remove(src)
    os.remove(dst)


def test_backup_cria_diretorio():
    src = tempfile.mktemp(suffix=".db")
    d = tempfile.mkdtemp()
    dst = os.path.join(d, "sub", "nested", "bkp.db")
    s = Storage(src)
    s.apply_scan("a.com", [])
    s.backup(dst)                  # o diretório aninhado é criado
    s.close()
    assert os.path.exists(dst)
    # o arquivo é abrível como SQLite
    conn = sqlite3.connect(dst)
    conn.execute("PRAGMA integrity_check")
    conn.close()
    os.remove(src)
    os.remove(dst)
