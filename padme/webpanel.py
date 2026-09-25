"""Painel web read-only da superfície de ataque.

Serve uma página HTML (stdlib, sem dependências) que lê o padme.db e mostra,
por alvo, o estado atual agrupado por categoria e os últimos eventos. Só
leitura — não altera nada. Bind em localhost por padrão.
"""

from __future__ import annotations

import html
import http.server
import socketserver
from datetime import datetime

from .config import Config
from .storage import Storage

_KIND_ORDER = ["takeover", "cert_expiry", "wildcard", "subdomain", "port", "http", "tls", "dns"]
_ARROW = {"added": "+", "removed": "-", "changed": "~"}

_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#c9d1d9;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.wrap{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:#8b949e;font-size:12px;margin-bottom:24px}
.tgt{border:1px solid #30363d;border-radius:10px;margin:0 0 20px;overflow:hidden}
.tgt h2{font-size:15px;margin:0;padding:12px 16px;background:#161b22;border-bottom:1px solid #30363d}
.tgt h2 .badge{color:#8b949e;font-weight:400;font-size:12px;margin-left:8px}
.kind{padding:8px 16px;border-bottom:1px solid #21262d}
.kind:last-child{border-bottom:0}
.kind b{color:#58a6ff;font-size:11px;letter-spacing:.06em}
.row{padding:2px 0 2px 12px;white-space:pre-wrap;word-break:break-all}
.k{color:#c9d1d9}
.v{color:#8b949e}
.ev{padding:8px 16px}
.ev .line{padding:1px 0 1px 12px}
.add{color:#3fb950}.rem{color:#f85149}.chg{color:#d29922}
.empty{color:#8b949e;padding:16px}
footer{color:#8b949e;font-size:11px;margin-top:24px;text-align:center}
"""


def _esc(s) -> str:
    return html.escape(str(s or ""))


def _render(cfg: Config) -> str:
    storage = Storage(cfg.db_path)
    try:
        rows = storage.all_state(cfg.targets)
        events = {t: storage.recent_events(t, 25) for t in cfg.targets}
    finally:
        storage.close()

    by_target: dict[str, dict[str, list]] = {}
    for r in rows:
        by_target.setdefault(r["target"], {}).setdefault(r["kind"], []).append(r)

    parts = [
        "<!doctype html><html lang=pt-br><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        "<meta http-equiv=refresh content=30>",
        "<title>Padmé — superfície</title><style>", _CSS, "</style></head><body><div class=wrap>",
        "<h1>🛰️ Padmé — superfície de ataque</h1>",
        f"<div class=sub>{len(rows)} itens · atualizado {datetime.now():%Y-%m-%d %H:%M:%S} · atualiza sozinho a cada 30s</div>",
    ]

    for target in cfg.targets:
        kinds = by_target.get(target, {})
        total = sum(len(v) for v in kinds.values())
        parts.append(f"<div class=tgt><h2>{_esc(target)}<span class=badge>{total} itens</span></h2>")
        if not kinds:
            parts.append("<div class=empty>sem baseline ainda — rode um scan.</div>")
        for kind in _KIND_ORDER:
            items = kinds.get(kind)
            if not items:
                continue
            parts.append(f"<div class=kind><b>{kind.upper()}</b>")
            for it in sorted(items, key=lambda x: x["key"]):
                val = f"  <span class=v>{_esc(it['value'])}</span>" if it["value"] else ""
                parts.append(f"<div class=row><span class=k>{_esc(it['key'])}</span>{val}</div>")
            parts.append("</div>")

        evs = events.get(target, [])
        if evs:
            parts.append("<div class=ev><b style='color:#58a6ff;font-size:11px'>ÚLTIMOS EVENTOS</b>")
            for e in evs:
                cls = {"added": "add", "removed": "rem", "changed": "chg"}[e.event_type.value]
                val = e.new_value if e.event_type.value != "removed" else e.old_value
                parts.append(
                    f"<div class='line {cls}'>{_ARROW[e.event_type.value]} "
                    f"[{e.kind.value}] {_esc(e.key)} {_esc(val)}</div>"
                )
            parts.append("</div>")
        parts.append("</div>")

    parts.append("<footer>Padmé · painel read-only</footer></div></body></html>")
    return "".join(parts)


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8787) -> None:
    page_cfg = cfg

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = _render(page_cfg).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True  # evita "Address already in use" ao reiniciar
        daemon_threads = True

    with Server((host, port), Handler) as httpd:
        print(f"Painel em http://{host}:{port}  (Ctrl+C para parar)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nEncerrando painel.")
