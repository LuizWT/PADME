"""API REST/JSON read-only e versionada (`/api/v1/...`).

Formaliza o que o `/export` já fazia (JSON sob token) como contrato estável para
automação: SIEM, ticketing, dashboards próprios. Tudo é **GET** e **somente
leitura** — ações de escrita (ack/suppress de finding) dependem do lifecycle de
finding, que ainda não existe (ver ideias.md), então nem são roteadas.

Design (ideias.md §4):
  - versionada em `/api/v1`; `schema_version` em toda resposta (contrato aditivo);
  - mesma auth **Bearer** do painel; sem token, só serve em loopback;
  - reusa o servidor endurecido do painel (teto de conexões, timeout, headers);
  - lê o banco em modo read-only (nunca escreve nem migra).

Endpoints:
  GET /api/v1                 -> metadados e lista de endpoints
  GET /api/v1/surface         -> estado atual (mesmos campos do export)
  GET /api/v1/events          -> eventos com severidade/confiança/razões (risk.assess)
  GET /api/v1/health          -> liveness por alvo (último scan, inconclusivos)

Filtros comuns: ?target= (exato, ou substring se não casar exato), ?kind=.
Eventos: ?type=added|removed|changed, ?min_severity=low|medium|high|critical,
?since=<unix|ISO-8601>. Paginação: ?limit= (1..1000), ?offset=.
"""

from __future__ import annotations

import http.server
import json
import urllib.parse
from datetime import datetime, timezone

from . import __version__
from .config import Config
from .notify.webhook import event_to_dict
from .risk import Level, parse_level, severity
from .storage import Storage, StorageOutdated
from .webpanel import _SEC_RESPONSE_HEADERS, PanelServer, _bearer_ok

API_SCHEMA_VERSION = 1
_PREFIX = "/api/v1"
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 1000
_EVENTS_CAP = 5000          # teto de eventos lidos antes de filtrar por severidade


def _open_ro(cfg: Config) -> Storage | None:
    """Abre o banco só-leitura; inexistente -> None (API responde vazio)."""
    try:
        return Storage(cfg.db_path, readonly=True)
    except FileNotFoundError:
        return None


def _parse_int(params: dict, name: str, default: int, lo: int, hi: int) -> int:
    """Inteiro de um query param, preso em [lo, hi]; inválido -> default."""
    raw = params.get(name, [None])[0]
    if raw is None:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except (TypeError, ValueError):
        return default


def _parse_since(raw: str | None) -> float | None:
    """`since` como unix (segundos) ou ISO-8601; None se ausente/inválido."""
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        txt = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _match_target(rows: list[dict], only: str | None, key: str = "target") -> list[dict]:
    """Mesma regra do export: casa exato; se nada, cai p/ substring."""
    if not only:
        return rows
    exact = [r for r in rows if r[key] == only]
    return exact or [r for r in rows if only in r[key]]


def _surface(cfg: Config, params: dict) -> dict:
    only = params.get("target", [None])[0]
    kind = params.get("kind", [None])[0]
    storage = _open_ro(cfg)
    rows = []
    if storage is not None:
        try:
            rows = storage.all_state()
        finally:
            storage.close()
    rows = _match_target(rows, only)
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    items = [{
        "source": cfg.source, "target": r["target"], "kind": r["kind"], "key": r["key"],
        "value": r["value"],
        "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"]),
        "metadata": r.get("metadata") or {},
    } for r in rows]
    return _page(items, params)


def _events(cfg: Config, params: dict) -> dict:
    only = params.get("target", [None])[0]
    kinds = [k for k in params.get("kind", []) if k]
    types = [t for t in params.get("type", []) if t]
    since = _parse_since(params.get("since", [None])[0])
    min_sev = params.get("min_severity", [None])[0]
    min_level = parse_level(min_sev, Level.DEBUG) if min_sev else Level.DEBUG

    storage = _open_ro(cfg)
    events = []
    truncated = False
    if storage is not None:
        try:
            # alvo exato vira filtro no SQL; substring fica para o Python
            sql_targets = [only] if (only and only in cfg.targets) else None
            got = storage.query_events(targets=sql_targets, kinds=kinds or None,
                                       event_types=types or None, since_ts=since,
                                       cap=_EVENTS_CAP)
            truncated = len(got) > _EVENTS_CAP
            events = got[:_EVENTS_CAP]
        finally:
            storage.close()
    if only and not (only in cfg.targets):   # substring: filtra no Python
        events = [e for e in events if only in e.target]
    if min_level > Level.DEBUG:
        events = [e for e in events if severity(e) >= min_level]
    page = _page([event_to_dict(e) for e in events], params)
    if truncated:
        page["truncated"] = True   # bateu no teto: refine os filtros / use since
    return page


def _health(cfg: Config, params: dict) -> dict:
    storage = _open_ro(cfg)
    targets = []
    if storage is not None:
        try:
            for t in cfg.targets:
                m = storage.target_meta(t) or {}
                targets.append({
                    "target": t,
                    "baseline": bool(m.get("baseline_initialized")),
                    "last_scan_at": _iso(m.get("last_scan_at")),
                    "last_success_at": _iso(m.get("last_success_at")),
                    "last_error_count": m.get("last_error_count"),
                    "last_inconclusive": m.get("last_inconclusive") or 0,
                    "last_partial": bool(m.get("last_partial")),
                })
        finally:
            storage.close()
    return {"targets": targets}


def _meta(cfg: Config, params: dict) -> dict:
    return {
        "service": "padme",
        "version": __version__,
        "source": cfg.source,
        "targets": len(cfg.targets),
        "endpoints": [f"{_PREFIX}", f"{_PREFIX}/surface", f"{_PREFIX}/events",
                      f"{_PREFIX}/health"],
    }


_HANDLERS = {
    _PREFIX: _meta,
    f"{_PREFIX}/surface": _surface,
    f"{_PREFIX}/events": _events,
    f"{_PREFIX}/health": _health,
}


def _iso(ts) -> str | None:
    """unix -> ISO-8601 UTC (ou None)."""
    if ts in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError):
        return None


def _page(items: list[dict], params: dict) -> dict:
    """Envelope paginado comum: total + fatia [offset:offset+limit]."""
    limit = _parse_int(params, "limit", _DEFAULT_LIMIT, 1, _MAX_LIMIT)
    offset = _parse_int(params, "offset", 0, 0, 1_000_000_000)
    total = len(items)
    window = items[offset:offset + limit]
    return {"count": len(window), "total": total, "limit": limit, "offset": offset,
            "items": window}


def respond(cfg: Config, route: str, params: dict) -> tuple[int, dict]:
    """Resolve uma rota já autenticada. Devolve (status, corpo). O corpo sempre
    leva `schema_version` (contrato aditivo e versionado)."""
    handler = _HANDLERS.get(route)
    if handler is None:
        return 404, {"schema_version": API_SCHEMA_VERSION, "error": "not_found",
                     "detail": f"rota desconhecida; veja {_PREFIX}"}
    body = handler(cfg, params)
    body["schema_version"] = API_SCHEMA_VERSION
    return 200, body


def make_handler(cfg: Config, auth_token: str | None):
    """Fábrica do handler (fecha sobre cfg/token). Separada de `serve` p/ teste
    sem `serve_forever`."""

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "padme"
        sys_version = ""
        timeout = 10

        def _write(self, code: int, body: dict, extra=None):
            payload = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            for k, v in _SEC_RESPONSE_HEADERS.items():
                self.send_header(k, v)
            for k, v in (extra or []):
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def do_GET(self):
            if auth_token is not None and not _bearer_ok(
                    self.headers.get("Authorization"), auth_token):
                # API é p/ automação: só Bearer (nada de prompt Basic do navegador)
                self._write(401, {"schema_version": API_SCHEMA_VERSION,
                                  "error": "unauthorized"},
                            [("WWW-Authenticate", 'Bearer realm="padme"')])
                return
            parsed = urllib.parse.urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"
            if route == "/" or route == "/api":
                route = _PREFIX   # cortesia: raiz aponta p/ a versão atual
            try:
                code, body = respond(cfg, route, urllib.parse.parse_qs(parsed.query))
            except StorageOutdated as exc:
                self._write(503, {"schema_version": API_SCHEMA_VERSION,
                                  "error": "storage_outdated", "detail": str(exc)})
                return
            self._write(code, body)

        do_HEAD = do_GET

        def log_message(self, *args):
            pass  # nunca loga requests (um token poderia estar num header)

    return Handler


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8788,
          token: str | None = None) -> None:
    handler = make_handler(cfg, token or None)
    with PanelServer((host, port), handler) as httpd:
        posture = "com token" if token else "SEM auth"
        print(f"API em http://{host}:{port}{_PREFIX}  ({posture} · Ctrl+C para parar)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nEncerrando API.")
