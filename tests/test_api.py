"""API read-only /api/v1: roteamento, filtros, paginação, severidade e auth,
exercitados contra um servidor real em porta efêmera."""

import json
import tempfile
import threading
import urllib.error
import urllib.request

from padme.api import API_SCHEMA_VERSION, make_handler, respond
from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.webpanel import PanelServer


def _seed(db: str) -> None:
    s = Storage(db)
    try:
        s.apply_scan("a.com", [])  # baseline (sem eventos)
        s.apply_scan("a.com", [
            Record(Kind.PORT, "a.com:443", "open"),
            Record(Kind.PORT, "a.com:3389", "open", metadata={"port": 3389}),
            Record(Kind.HTTP, "https://a.com", "200"),
        ])
        s.apply_scan("b.com", [])
        s.apply_scan("b.com", [Record(Kind.PORT, "b.com:22", "open", metadata={"port": 22})])
    finally:
        s.close()


def _cfg():
    db = tempfile.mktemp(suffix=".db")
    _seed(db)
    return Config(targets=["a.com", "b.com"], db_path=db), db


def _serve(cfg, token=None):
    srv = PanelServer(("127.0.0.1", 0), make_handler(cfg, token))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def _get(port, path, token=None, method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore"), dict(e.headers)


# ── respond(): roteamento e contrato (puro, sem rede) ─────────────────────────
def test_meta_lista_endpoints():
    cfg, _ = _cfg()
    code, body = respond(cfg, "/api/v1", {})
    assert code == 200
    assert body["schema_version"] == API_SCHEMA_VERSION
    assert body["service"] == "padme" and body["targets"] == 2
    assert "/api/v1/events" in body["endpoints"]


def test_rota_desconhecida_404():
    cfg, _ = _cfg()
    code, body = respond(cfg, "/api/v1/nope", {})
    assert code == 404 and body["error"] == "not_found"


def test_surface_filtra_e_pagina():
    cfg, _ = _cfg()
    _, body = respond(cfg, "/api/v1/surface", {})
    assert body["total"] == 4 and body["count"] == 4   # 3 de a.com + 1 de b.com
    # filtro por alvo (exato) + kind
    _, only = respond(cfg, "/api/v1/surface", {"target": ["a.com"], "kind": ["port"]})
    assert only["total"] == 2 and all(i["kind"] == "port" for i in only["items"])
    # paginação
    _, p = respond(cfg, "/api/v1/surface", {"limit": ["1"], "offset": ["1"]})
    assert p["count"] == 1 and p["total"] == 4 and p["offset"] == 1
    # item carrega os campos do export
    assert {"source", "target", "kind", "key", "value", "first_seen",
            "last_seen", "metadata"} <= set(body["items"][0])


def test_surface_target_substring_quando_nao_casa_exato():
    cfg, _ = _cfg()
    _, body = respond(cfg, "/api/v1/surface", {"target": ["a.c"]})  # substring
    assert body["total"] == 3 and all(i["target"] == "a.com" for i in body["items"])


def test_events_severidade_tipo_e_envelope():
    cfg, _ = _cfg()
    _, allev = respond(cfg, "/api/v1/events", {})
    assert allev["total"] >= 4
    # cada evento traz severidade/confiança/risk (contrato do webhook)
    first = allev["items"][0]
    assert {"severity", "confidence", "risk", "kind", "type", "key"} <= set(first)
    # min_severity=critical deixa só o 3389 (porta de acesso remoto = CRITICAL)
    _, crit = respond(cfg, "/api/v1/events", {"min_severity": ["critical"]})
    assert crit["total"] >= 1
    assert all(e["severity"] == "critical" for e in crit["items"])
    assert any(":3389" in e["key"] for e in crit["items"])
    # filtro por tipo
    _, added = respond(cfg, "/api/v1/events", {"type": ["added"]})
    assert added["total"] >= 1 and all(e["type"] == "added" for e in added["items"])


def test_events_since_descarta_antigos():
    cfg, _ = _cfg()
    future = "2999-01-01T00:00:00Z"
    _, body = respond(cfg, "/api/v1/events", {"since": [future]})
    assert body["total"] == 0


def test_health_por_alvo():
    cfg, _ = _cfg()
    _, body = respond(cfg, "/api/v1/health", {})
    alvos = {t["target"]: t for t in body["targets"]}
    assert set(alvos) == {"a.com", "b.com"}
    assert alvos["a.com"]["baseline"] is True
    assert "last_scan_at" in alvos["a.com"]


# ── servidor real: auth e JSON ────────────────────────────────────────────────
def test_sem_token_serve_em_loopback():
    cfg, _ = _cfg()
    srv, port = _serve(cfg, token=None)
    try:
        code, body, headers = _get(port, "/api/v1/surface")
        assert code == 200
        doc = json.loads(body)
        assert doc["schema_version"] == API_SCHEMA_VERSION
        assert headers.get("Content-Type", "").startswith("application/json")
        assert headers.get("X-Content-Type-Options") == "nosniff"
    finally:
        srv.shutdown()


def test_token_exige_bearer():
    cfg, _ = _cfg()
    srv, port = _serve(cfg, token="sek")
    try:
        code, _b, headers = _get(port, "/api/v1/surface")          # sem token
        assert code == 401 and "Bearer" in headers.get("WWW-Authenticate", "")
        code, _b, _h = _get(port, "/api/v1/surface", token="errado")
        assert code == 401
        code, body, _h = _get(port, "/api/v1/surface", token="sek")
        assert code == 200 and json.loads(body)["total"] == 4
    finally:
        srv.shutdown()


def test_raiz_aponta_para_versao_e_head_sem_corpo():
    cfg, _ = _cfg()
    srv, port = _serve(cfg, token=None)
    try:
        code, body, _h = _get(port, "/")
        assert code == 200 and json.loads(body)["service"] == "padme"
        code, body, headers = _get(port, "/api/v1", method="HEAD")
        assert code == 200 and body == "" and int(headers.get("Content-Length", "0")) > 0
    finally:
        srv.shutdown()


def test_banco_inexistente_responde_vazio():
    cfg = Config(targets=["a.com"], db_path=tempfile.mktemp(suffix=".db"))
    _, body = respond(cfg, "/api/v1/surface", {})
    assert body["total"] == 0 and body["items"] == []
    _, ev = respond(cfg, "/api/v1/events", {})
    assert ev["total"] == 0
