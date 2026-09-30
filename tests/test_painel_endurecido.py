"""Painel endurecido: banco só-leitura, login pelo navegador e teto de conexões."""

import base64
import os
import socket
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage, StorageOutdated
from padme.webpanel import PanelServer, _auth_ok, _render, make_handler


def _db_com_dados():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [Record(Kind.PORT, "a.com:443", "open")])
    s.close()
    return db


# ── banco só-leitura ────────────────────────────────────────────────────────
def test_storage_readonly_nao_escreve():
    db = _db_com_dados()
    try:
        mtime = os.path.getmtime(db)
        ro = Storage(db, readonly=True)
        assert ro.all_state()                              # lê normalmente
        with pytest.raises(sqlite3.OperationalError):      # qualquer escrita é recusada
            ro.apply_scan("a.com", [])
        ro.close()
        assert os.path.getmtime(db) == mtime
    finally:
        os.remove(db)


def test_painel_sem_banco_nao_cria_arquivo():
    db = tempfile.mktemp(suffix=".db")
    html = _render(Config(targets=["a.com"], db_path=db))
    assert "a.com" in html and not os.path.exists(db)      # antes criava um padme.db vazio


def test_schema_antigo_nao_e_migrado_pelo_painel():
    db = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 3")
    con.commit(); con.close()
    try:
        with pytest.raises(StorageOutdated):
            Storage(db, readonly=True)
        con = sqlite3.connect(db)
        assert con.execute("PRAGMA user_version").fetchone()[0] == 3   # intocado
        con.close()
    finally:
        os.remove(db)


# ── login pelo navegador (Basic) além de Bearer ─────────────────────────────
def _basic(user, pwd):
    return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()


def test_auth_ok_aceita_basic_e_bearer():
    assert _auth_ok(_basic("qualquer", "sekret"), "sekret")
    assert _auth_ok(_basic("", "sekret"), "sekret")        # usuário é ignorado
    assert _auth_ok("Bearer sekret", "sekret")
    assert not _auth_ok(_basic("x", "errado"), "sekret")
    assert not _auth_ok("Basic !!!nao-e-base64", "sekret")
    assert not _auth_ok("Basic " + base64.b64encode(b"sem-dois-pontos").decode(), "sekret")
    assert not _auth_ok("Digest abc", "sekret")
    assert not _auth_ok(None, "sekret")


def _serve(cfg, token):
    srv = PanelServer(("127.0.0.1", 0), make_handler(cfg, exposed=False, auth_token=token))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(port, path, auth=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.headers


def test_navegador_recebe_desafio_basic_e_entra_com_o_token():
    db = _db_com_dados()
    srv, port = _serve(Config(targets=["a.com"], db_path=db), "sekret")
    try:
        code, headers = _get(port, "/")
        assert code == 401
        assert any(v.startswith("Basic") for v in headers.get_all("WWW-Authenticate"))
        assert _get(port, "/", _basic("eu", "sekret"))[0] == 200
        assert _get(port, "/export?fmt=csv", _basic("eu", "sekret"))[0] == 200
        assert _get(port, "/", _basic("eu", "errado"))[0] == 401
    finally:
        srv.shutdown(); srv.server_close(); os.remove(db)


def test_schema_antigo_responde_503():
    db = tempfile.mktemp(suffix=".db")
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = 3")
    con.commit(); con.close()
    srv, port = _serve(Config(targets=["a.com"], db_path=db), None)
    try:
        assert _get(port, "/")[0] == 503
    finally:
        srv.shutdown(); srv.server_close(); os.remove(db)


# ── conexões lentas não esgotam o servidor ──────────────────────────────────
def test_teto_de_conexoes_recusa_excedente():
    db = _db_com_dados()

    class _Pequeno(PanelServer):
        max_connections = 2

    srv = _Pequeno(("127.0.0.1", 0), make_handler(Config(targets=["a.com"], db_path=db),
                                                  exposed=False, auth_token=None))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    lentas = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]  # nunca mandam nada
    try:
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", port))
        extra.settimeout(2)
        assert extra.recv(1) == b""        # lotado: fechada na hora, sem thread nova
        extra.close()
    finally:
        for c in lentas:
            c.close()
        srv.shutdown(); srv.server_close(); os.remove(db)


def test_handler_tem_timeout_de_socket():
    handler = make_handler(Config(targets=["a.com"], db_path="x.db"), exposed=False, auth_token=None)
    assert handler.timeout and handler.timeout <= 30
