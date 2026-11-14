"""Servidor HTTP do painel: rotas, cabeçalhos de segurança, ações POST com
CSRF, atualização ao vivo (/live, Server-Sent Events) e o modo em thread.
"""

from __future__ import annotations

import hmac
import http.server
import os
import secrets
import socketserver
import sqlite3
import threading
import time
import urllib.parse

from ..findings import (
    ACTIONS,
)
from ..storage import Storage, StorageOutdated
from .auth import (
    _auth_ok,
    _basic_user,
    _same_origin,
)
from .html import (
    _esc,
)
from .layout import (
    _page,
)
from .pages import (
    _render,
    render_export,
    render_vantage,
)

_ROUTES = ("/", "/export", "/vantage", "/live")  # rotas conhecidas (após auth)


# /live: de quanto em quanto tempo olha o banco, ping que mantém a conexão viva
# atrás de proxy e vida máxima da conexão (o navegador reconecta sozinho; assim
# uma aba esquecida não segura uma vaga do servidor para sempre).
_LIVE_POLL = 1.0


_LIVE_PING = 15.0


_LIVE_MAX = 600.0


def _db_stamp(db_path: str) -> tuple:
    """Assinatura barata do banco: (mtime, tamanho) do arquivo e do -wal. Toda
    gravação do monitor (WAL) muda o -wal. Um -wal VAZIO conta como ausente: a
    própria leitura do painel cria um vazio quando não há, e isso não é mudança."""
    out = []
    for suffix in ("", "-wal"):
        try:
            st = os.stat(db_path + suffix)
        except OSError:
            out.append(None)
            continue
        out.append(None if suffix and st.st_size == 0 else (st.st_mtime_ns, st.st_size))
    return tuple(out)


# CSP compatível com o HTML real do painel: <style>/<script> e style="" inline
# (daí 'unsafe-inline'), ícones/imagens só como data:, formulários (filtro GET,
# ações POST) só p/ a mesma origem. Sem fontes/JS externos — 100% self-contained.
# `connect-src 'self'`: o JS só conversa com o próprio painel (/live e a busca
# do conteúdo novo).
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src data:; connect-src 'self'; form-action 'self'; base-uri 'none'; "
        "frame-ancestors 'none'")


_SEC_RESPONSE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": _CSP,
}


class PanelServer(socketserver.ThreadingTCPServer):
    """Servidor com TETO de conexões simultâneas: acima de `max_connections`,
    a conexão nova é fechada na hora em vez de abrir mais uma thread — conexões
    lentas (slowloris) não esgotam a máquina. Cada conexão ainda tem timeout
    próprio no handler."""
    allow_reuse_address = True
    daemon_threads = True
    max_connections = 32

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)  # lotado: recusa sem abrir thread
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


# ── ações de finding (POST) ─────────────────────────────────────────────────
_MAX_FORM_BYTES = 4096  # um formulário de ação tem id + ação + motivo (<= 500)


def _apply_action(cfg, form: dict, actor: str) -> tuple[int, str]:
    """Aplica a ação no banco (conexão de ESCRITA só durante o POST; o render
    continua read-only). Devolve (status HTTP, mensagem de erro)."""
    fid = (form.get("id") or [""])[0]
    action = (form.get("action") or [""])[0]
    reason = (form.get("reason") or [""])[0]
    if action not in ACTIONS:
        return 400, "ação inválida."
    try:
        storage = Storage(cfg.db_path)
    except (sqlite3.Error, OSError):
        return 503, ("o banco não aceita escrita (volume só-leitura ou sem permissão): "
                     "use `padme finding` onde o monitor roda, ou web.actions: false.")
    try:
        storage.set_finding_status(fid, action, reason=reason, actor=actor)
    except ValueError as exc:
        return 400, str(exc)
    except sqlite3.Error:
        return 503, "falha ao gravar no banco (ocupado ou só-leitura): tente de novo."
    finally:
        storage.close()
    return 303, ""


def _action_error_page(msg: str, target: str) -> bytes:
    back = "/" + (f"?target={urllib.parse.quote(target)}" if target else "") + "#problems"
    body = ("<header class=pagehead><div><h1>Ação não aplicada</h1>"
            "<p>nada foi alterado no finding</p></div></header>"
            f"<div class=banner><span>{_esc(msg)}</span></div>"
            f"<a class=xbtn href='{_esc(back)}'>← voltar aos problemas</a>")
    return _page("Padmé — ação", "", body).encode("utf-8")


def make_handler(page_cfg, exposed: bool, auth_token: str | None):
    """Fábrica do handler HTTP (fecha sobre cfg/exposed/token). Separada de
    `serve` para ser testável sem depender de `serve_forever`.

    Ações de finding (POST /finding) só ligam com `web.actions` e se o painel
    NÃO estiver exposto sem auth — fora de localhost sem token, qualquer um da
    rede mudaria o estado. O token de CSRF é aleatório por processo e vai no
    formulário; uma página de outra origem não consegue lê-lo."""
    actions_on = bool(page_cfg.web.actions) and (not exposed or auth_token is not None)
    csrf = secrets.token_hex(32) if actions_on else ""

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "padme"  # não anuncia versão do Python/BaseHTTPServer
        sys_version = ""
        timeout = 10  # s por operação de socket: conexão lenta não prende a thread

        def _write(self, code: int, ctype: str, body: bytes, extra: dict | None = None):
            """Escreve a resposta SEMPRE com os headers de segurança do painel."""
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _SEC_RESPONSE_HEADERS.items():
                self.send_header(k, v)
            pairs = extra.items() if isinstance(extra, dict) else (extra or [])
            for k, v in pairs:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _deny(self):
            # 401 mínimo: não revela quais rotas existem nem detalhes internos.
            # Basic primeiro: é o que faz o navegador abrir o prompt de login.
            self._write(401, "text/plain; charset=utf-8", b"401 Unauthorized\n",
                        [("WWW-Authenticate", 'Basic realm="padme", charset="UTF-8"'),
                         ("WWW-Authenticate", 'Bearer realm="padme"')])

        def do_GET(self):
            # auth ANTES do roteamento: cobre /, /export, /vantage e qualquer
            # rota futura de uma vez. Sem token configurado, não exige nada.
            if auth_token is not None and not _auth_ok(
                    self.headers.get("Authorization"), auth_token):
                self._deny()
                return
            parsed = urllib.parse.urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"
            if route not in _ROUTES:
                self._write(404, "text/plain; charset=utf-8", b"404 Not Found\n")
                return
            if route == "/live":
                self._live()
                return
            try:
                self._route(route, urllib.parse.parse_qs(parsed.query))
            except StorageOutdated as exc:
                # o painel só LÊ: quem migra o schema é o monitor/scan/doctor
                self._write(503, "text/plain; charset=utf-8", f"503 {exc}\n".encode("utf-8"))

        def _live(self):
            """Server-Sent Events: `event: change` quando o banco muda. Só avisa;
            o navegador busca a página de novo (mesma auth, mesmo render)."""
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("X-Accel-Buffering", "no")   # nginx: não segurar o stream
            for k, v in _SEC_RESPONSE_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            db = str(page_cfg.db_path)
            last = _db_stamp(db)
            started = pinged = time.monotonic()
            try:
                self.wfile.write(b"retry: 3000\n\n")
                self.wfile.flush()
                while time.monotonic() - started < _LIVE_MAX:
                    time.sleep(_LIVE_POLL)
                    cur = _db_stamp(db)
                    if cur != last:
                        last = cur
                        self.wfile.write(b"event: change\ndata: 1\n\n")
                    elif time.monotonic() - pinged >= _LIVE_PING:
                        self.wfile.write(b": ping\n\n")
                    else:
                        continue
                    pinged = time.monotonic()
                    self.wfile.flush()
            except OSError:
                return   # aba fechada / conexão caiu: o navegador reconecta se quiser

        def do_POST(self):
            if auth_token is not None and not _auth_ok(
                    self.headers.get("Authorization"), auth_token):
                self._deny()
                return
            route = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
            if route != "/finding":
                self._write(404, "text/plain; charset=utf-8", b"404 Not Found\n")
                return
            if not actions_on:
                self._write(403, "text/plain; charset=utf-8",
                            "403 ações desligadas: painel read-only (web.actions=false ou "
                            "exposto sem token). Use `padme finding`.\n".encode("utf-8"))
                return
            if not _same_origin(self.headers):
                self._write(403, "text/plain; charset=utf-8", b"403 origem cruzada recusada\n")
                return
            try:
                size = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                size = -1
            if not 0 < size <= _MAX_FORM_BYTES:
                self._write(413, "text/plain; charset=utf-8", b"413 formulario invalido ou grande demais\n")
                return
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype != "application/x-www-form-urlencoded":
                self._write(415, "text/plain; charset=utf-8", b"415 tipo de conteudo nao suportado\n")
                return
            try:
                form = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8", "replace"),
                                             max_num_fields=10)
            except ValueError:
                self._write(400, "text/plain; charset=utf-8", b"400 formulario invalido\n")
                return
            sent = (form.get("csrf") or [""])[0].encode("utf-8")
            if not hmac.compare_digest(sent, csrf.encode("utf-8")):
                self._write(403, "text/plain; charset=utf-8",
                            "403 token de CSRF inválido — recarregue o painel e tente de novo.\n"
                            .encode("utf-8"))
                return
            target = (form.get("target") or [""])[0]
            actor = _basic_user(self.headers.get("Authorization")) or "painel"
            code, msg = _apply_action(page_cfg, form, actor)
            if code == 303:
                # quote() no alvo: vem do formulário, um \r\n viraria header injection
                loc = "/" + (f"?target={urllib.parse.quote(target)}" if target else "") + "#problems"
                self._write(303, "text/plain; charset=utf-8", b"", {"Location": loc})
            else:
                self._write(code, "text/html; charset=utf-8", _action_error_page(msg, target))

        def _route(self, route: str, params: dict) -> None:
            only = params.get("target", [None])[0]
            if route == "/export":
                fmt = (params.get("fmt", ["json"])[0] or "json").lower()
                fmt = "csv" if fmt == "csv" else "json"
                text, ctype = render_export(page_cfg, only, fmt)
                # sanitiza o nome do arquivo: `only` vem do ?target= (atacante-
                # controlado); um \r\n aqui permitiria header injection.
                safe = "".join(c for c in (only or "todos") if c.isalnum() or c in "._-")
                fname = f"padme-{safe or 'todos'}.{fmt}"
                self._write(200, ctype, text.encode("utf-8"),
                            {"Content-Disposition": f'attachment; filename="{fname}"'})
            elif route == "/vantage":
                self._write(200, "text/html; charset=utf-8",
                            render_vantage(page_cfg).encode("utf-8"))
            else:
                body = _render(page_cfg, exposed=exposed, only=only,
                               authed=auth_token is not None, csrf=csrf).encode("utf-8")
                self._write(200, "text/html; charset=utf-8", body)

        def log_message(self, *args):
            pass  # nunca loga requests (evita vazar o token de um header em log)

    return Handler


def start_background(cfg, host: str = "127.0.0.1", port: int = 8787, exposed: bool = False,
                     token: str | None = None) -> PanelServer:
    """Sobe o painel numa thread daemon (o monitor o serve junto, num terminal
    só) e devolve o servidor. Porta ocupada -> OSError para quem chamou."""
    httpd = PanelServer((host, port), make_handler(cfg, exposed, token or None))
    threading.Thread(target=httpd.serve_forever, name="padme-painel", daemon=True).start()
    return httpd


def serve(cfg, host: str = "127.0.0.1", port: int = 8787, exposed: bool = False,
          token: str | None = None) -> None:
    auth_token = token or None  # "" também desliga a auth
    handler = make_handler(cfg, exposed, auth_token)
    with PanelServer((host, port), handler) as httpd:
        posture = "com token" if auth_token else "SEM auth"
        print(f"Painel em http://{host}:{port}  ({posture} · Ctrl+C para parar)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nEncerrando painel.")
