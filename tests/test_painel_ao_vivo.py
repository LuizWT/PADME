"""Painel em tempo real: /live (Server-Sent Events) avisa quando o banco muda."""

import base64
import os
import socket
import tempfile
import threading
import time

import pytest

from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.web import server


@pytest.fixture
def painel(monkeypatch):
    monkeypatch.setattr(server, "_LIVE_POLL", 0.05)
    monkeypatch.setattr(server, "_LIVE_PING", 0.3)
    monkeypatch.setattr(server, "_LIVE_MAX", 3.0)
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [Record(Kind.PORT, "a.com:443", "open")])
    s.close()
    servers = []

    def subir(token=None):
        cfg = Config(targets=["a.com"], db_path=db)
        srv = server.PanelServer(("127.0.0.1", 0), server.make_handler(cfg, False, token))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield db, subir
    for srv in servers:
        srv.shutdown()
        srv.server_close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(db + suffix)
        except OSError:
            pass


def _abrir_live(port, auth=None):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    extra = f"Authorization: {auth}\r\n" if auth else ""
    sock.sendall(f"GET /live HTTP/1.1\r\nHost: 127.0.0.1\r\n{extra}\r\n".encode())
    return sock


def _ler_ate(sock, marca: bytes, limite=3.0) -> bytes:
    buf, fim = b"", time.time() + limite
    while marca not in buf and time.time() < fim:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def test_live_avisa_quando_o_banco_muda(painel):
    db, subir = painel
    sock = _abrir_live(subir())
    try:
        cab = _ler_ate(sock, b"retry: 3000")
        assert b"200" in cab.split(b"\r\n", 1)[0]
        assert b"text/event-stream" in cab and b"connect-src 'self'" in cab
        s = Storage(db)                                  # o monitor grava algo
        s.apply_scan("a.com", [Record(Kind.PORT, "a.com:22", "open")])
        s.close()
        assert b"event: change" in _ler_ate(sock, b"event: change")
    finally:
        sock.close()


def test_live_manda_ping_sem_mudanca_e_encerra_sozinho(painel):
    _, subir = painel
    sock = _abrir_live(subir())
    try:
        dados = _ler_ate(sock, b": ping")
        assert b": ping" in dados and b"event: change" not in dados
        sock.settimeout(5)
        resto = b""
        while True:                                      # _LIVE_MAX: o servidor fecha
            chunk = sock.recv(4096)
            if not chunk:
                break
            resto += chunk
    finally:
        sock.close()


def test_live_exige_o_mesmo_login_do_painel(painel):
    _, subir = painel
    port = subir(token="sekret")
    sock = _abrir_live(port)
    try:
        assert b"401" in _ler_ate(sock, b"\r\n\r\n").split(b"\r\n", 1)[0]
    finally:
        sock.close()
    basic = "Basic " + base64.b64encode(b"ana:sekret").decode()
    sock = _abrir_live(port, basic)
    try:
        assert b"retry: 3000" in _ler_ate(sock, b"retry: 3000")
    finally:
        sock.close()


def test_assinatura_do_banco_muda_com_gravacao_e_nao_com_leitura(painel):
    db, _ = painel
    antes = server._db_stamp(db)
    ro = Storage(db, readonly=True)
    ro.all_state()
    ro.close()
    assert server._db_stamp(db) == antes              # o painel lendo não dispara nada
    s = Storage(db)
    s.apply_scan("a.com", [Record(Kind.PORT, "a.com:8080", "open")])
    s.close()
    assert server._db_stamp(db) != antes
    assert server._db_stamp(db + ".nao-existe") == (None, None)
