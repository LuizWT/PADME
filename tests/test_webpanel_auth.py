"""Segurança do painel: bind default, autenticação Bearer e cobertura de rotas."""

import asyncio
import os
import tempfile
import threading
import urllib.error
import urllib.request

from padme.cli import _cmd_web, _resolve_web_token
from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.webpanel import PanelServer, _bearer_ok, make_handler


def _cfg_with_db():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [Record(Kind.PORT, "a.com:443", "open")])
    s.close()
    return Config(targets=["a.com"], db_path=db), db


# ── validação do header Bearer (constante) ───────────────────────────────────
def test_bearer_ok_casos():
    assert _bearer_ok("Bearer sekret", "sekret") is True
    assert _bearer_ok("bearer sekret", "sekret") is True       # case-insensitive no esquema
    assert _bearer_ok("Bearer errado", "sekret") is False
    assert _bearer_ok(None, "sekret") is False                 # ausente
    assert _bearer_ok("sekret", "sekret") is False             # sem esquema
    assert _bearer_ok("Basic sekret", "sekret") is False       # esquema errado
    assert _bearer_ok("Bearer", "sekret") is False             # malformado
    assert _bearer_ok("Bearer \x80\x81", "sekret") is False    # bytes não-ASCII: nega, não crasha


# ── bind default ─────────────────────────────────────────────────────────────
def test_bind_default_e_localhost():
    assert Config(targets=["a.com"]).web.bind == "127.0.0.1"


def _serve_in_thread(cfg, token):
    srv = PanelServer(("127.0.0.1", 0), make_handler(cfg, exposed=False, auth_token=token))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def _get(port, path, token=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")


def test_local_sem_token_serve_simples():
    cfg, db = _cfg_with_db()
    srv, port = _serve_in_thread(cfg, token=None)
    try:
        assert _get(port, "/")[0] == 200            # localhost sem token = simples
        assert _get(port, "/export?fmt=json")[0] == 200
    finally:
        srv.shutdown(); srv.server_close(); os.remove(db)


def test_token_protege_html_export_e_404():
    cfg, db = _cfg_with_db()
    srv, port = _serve_in_thread(cfg, token="sekret")
    try:
        # sem token -> 401 em TODAS as rotas
        assert _get(port, "/")[0] == 401
        assert _get(port, "/export?fmt=json")[0] == 401
        # token errado -> 401
        assert _get(port, "/", token="errado")[0] == 401
        # token certo -> 200 no HTML e no export
        assert _get(port, "/", token="sekret")[0] == 200
        assert _get(port, "/export?fmt=csv", token="sekret")[0] == 200
        # rota desconhecida (com token) -> 404, não vaza como 200
        assert _get(port, "/segredo", token="sekret")[0] == 404
    finally:
        srv.shutdown(); srv.server_close(); os.remove(db)


def test_export_filename_sanitizado_sem_header_injection():
    cfg, db = _cfg_with_db()
    srv, port = _serve_in_thread(cfg, token=None)
    try:
        # ?target= com CRLF não pode injetar header no Content-Disposition
        status, _ = _get(port, "/export?fmt=json&target=a%0d%0aX-Evil:1")
        assert status == 200                       # responde limpo, sem quebrar a resposta
    finally:
        srv.shutdown(); srv.server_close(); os.remove(db)


# ── resolução do token (env / yaml) sem passar pelo argv ─────────────────────
def test_resolve_token_env_e_yaml(monkeypatch):
    monkeypatch.delenv("PADME_WEB_TOKEN", raising=False)
    assert _resolve_web_token(Config(targets=["a.com"])) == ""
    monkeypatch.setenv("PADME_WEB_TOKEN", "from-env")
    assert _resolve_web_token(Config(targets=["a.com"])) == "from-env"


# ── exposição externa exige decisão consciente ──────────────────────────────
def test_exposto_sem_token_recusa(monkeypatch):
    monkeypatch.delenv("PADME_WEB_TOKEN", raising=False)
    cfg, db = _cfg_with_db()

    class Args:
        host = "0.0.0.0"; port = None; allow_no_auth = False

    try:
        rc = asyncio.run(_cmd_web(cfg, Args()))  # deve retornar 3 ANTES de servir
        assert rc == 3
    finally:
        os.remove(db)
