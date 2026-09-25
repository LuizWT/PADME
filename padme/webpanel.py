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
.tiles{display:flex;flex-wrap:wrap;gap:8px;padding:12px 16px;border-bottom:1px solid #21262d}
.tile{flex:1 1 88px;min-width:88px;border:1px solid #30363d;border-radius:8px;padding:8px 10px;background:#0f141a}
.tile .num{font-size:20px;font-weight:600;color:#c9d1d9;line-height:1.1}
.tile .lab{font-size:10px;letter-spacing:.05em;color:#8b949e;margin-top:2px;text-transform:uppercase}
.tile .sub{font-size:10px;color:#8b949e;margin-top:2px}
.tile.crit{border-color:#f85149}.tile.crit .num{color:#f85149}
.tile.warn{border-color:#d29922}.tile.warn .num{color:#d29922}
.trend{padding:8px 16px;border-bottom:1px solid #21262d}
.trend b{color:#58a6ff;font-size:11px;letter-spacing:.06em}
.trend svg{width:100%;height:auto;display:block;margin-top:6px}
.legend{color:#8b949e;font-size:11px;margin-top:4px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin:0 4px 0 10px;vertical-align:middle}
footer{color:#8b949e;font-size:11px;margin-top:24px;text-align:center}
"""

_TREND_ADD = "#3fb950"
_TREND_CHG = "#d29922"
_TREND_REM = "#f85149"


def _tile(num, lab: str, sub: str = "", cls: str = "") -> str:
    sub_html = f"<div class=sub>{_esc(sub)}</div>" if sub else ""
    klass = f"tile {cls}".strip()
    return (f"<div class='{klass}'><div class=num>{_esc(num)}</div>"
            f"<div class=lab>{_esc(lab)}</div>{sub_html}</div>")


def _stat_tiles(kinds: dict[str, list]) -> str:
    """Foto rápida da superfície atual: KPIs de leitura em 1s, com os achados
    críticos (takeover/wildcard/cert) destacados por cor de status."""
    subs = kinds.get("subdomain", [])
    live = sum(1 for s in subs if s["value"] == "live")
    quiet = sum(1 for s in subs if s["value"] == "quiet")

    tiles = [
        _tile(len(subs), "subdomínios", f"{live} live · {quiet} quiet" if subs else ""),
        _tile(len(kinds.get("http", [])), "serviços http"),
        _tile(len(kinds.get("port", [])), "portas abertas"),
        _tile(len(kinds.get("tls", [])), "certificados"),
    ]
    # críticos: só aparecem quando existem, com cor de status
    n_takeover = len(kinds.get("takeover", []))
    n_wildcard = len(kinds.get("wildcard", []))
    n_cert = len(kinds.get("cert_expiry", []))
    if n_takeover:
        tiles.append(_tile(n_takeover, "takeover", "crítico", cls="crit"))
    if n_cert:
        tiles.append(_tile(n_cert, "cert expirando", cls="warn"))
    if n_wildcard:
        tiles.append(_tile(n_wildcard, "wildcard dns", cls="warn"))
    return f"<div class=tiles>{''.join(tiles)}</div>"


def _trend_svg(series: list[dict], days: int) -> str:
    """Barras empilhadas de eventos/dia (added/changed/removed) — mostra se a
    superfície está crescendo, estável ou encolhendo. SVG inline, sem deps."""
    W, H = 720.0, 150.0
    pad_l, pad_r, pad_t, pad_b = 30.0, 8.0, 10.0, 22.0
    plot_w = W - pad_l - pad_r
    plot_h = H - pad_t - pad_b
    base_y = pad_t + plot_h
    max_total = max((d["total"] for d in series), default=0)

    parts = [f'<svg viewBox="0 0 {W:.0f} {H:.0f}" role="img" '
             f'aria-label="eventos por dia nos últimos {days} dias" '
             'preserveAspectRatio="none">']
    # linha de base + topo (grade discreta) com rótulo do máximo
    parts.append(f'<line x1="{pad_l}" y1="{base_y:.1f}" x2="{W - pad_r:.1f}" '
                 f'y2="{base_y:.1f}" stroke="#30363d" stroke-width="1"/>')
    if max_total > 0:
        parts.append(f'<line x1="{pad_l}" y1="{pad_t:.1f}" x2="{W - pad_r:.1f}" '
                     f'y2="{pad_t:.1f}" stroke="#21262d" stroke-width="1"/>')
        parts.append(f'<text x="{pad_l - 4:.1f}" y="{pad_t + 4:.1f}" '
                     'text-anchor="end" font-size="9" fill="#8b949e">'
                     f'{max_total}</text>')
        parts.append(f'<text x="{pad_l - 4:.1f}" y="{base_y:.1f}" '
                     'text-anchor="end" font-size="9" fill="#8b949e">0</text>')

    n = len(series)
    slot = plot_w / n if n else plot_w
    bar_w = max(1.0, slot - 2.0)
    scale = (plot_h / max_total) if max_total > 0 else 0.0

    def seg(x, y_bottom, h, color):
        # 2px de respiro no topo de cada segmento (fica entre os empilhados)
        drawn = h - 2 if h > 2 else h
        return (f'<rect x="{x:.1f}" y="{y_bottom - drawn:.1f}" width="{bar_w:.1f}" '
                f'height="{drawn:.1f}" fill="{color}" rx="1.5"/>')

    for i, d in enumerate(series):
        x = pad_l + i * slot + (slot - bar_w) / 2
        y_bottom = base_y  # o 1º segmento fica ancorado na base
        title = (f'{d["day"]}: +{d["added"]} added, ~{d["changed"]} changed, '
                 f'-{d["removed"]} removed')
        cells = []
        for key, color in (("added", _TREND_ADD), ("changed", _TREND_CHG),
                           ("removed", _TREND_REM)):
            h = d[key] * scale
            if h > 0:
                cells.append(seg(x, y_bottom, h, color))
                y_bottom -= h
        parts.append(f'<g><title>{_esc(title)}</title>{"".join(cells)}</g>')

    # rótulos de X: primeiro, meio, último (MM-DD)
    if n:
        for idx in sorted({0, n // 2, n - 1}):
            label = series[idx]["day"][5:]  # MM-DD
            cx = pad_l + idx * slot + slot / 2
            anchor = "start" if idx == 0 else ("end" if idx == n - 1 else "middle")
            parts.append(f'<text x="{cx:.1f}" y="{H - 6:.1f}" text-anchor="{anchor}" '
                         f'font-size="9" fill="#8b949e">{label}</text>')

    parts.append("</svg>")
    return "".join(parts)


def _esc(s) -> str:
    return html.escape(str(s or ""))


def _render(cfg: Config) -> str:
    trend_days = 30
    storage = Storage(cfg.db_path)
    try:
        rows = storage.all_state(cfg.targets)
        events = {t: storage.recent_events(t, 25) for t in cfg.targets}
        trend = {t: storage.events_per_day(t, trend_days) for t in cfg.targets}
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
        else:
            parts.append(_stat_tiles(kinds))
        for kind in _KIND_ORDER:
            items = kinds.get(kind)
            if not items:
                continue
            parts.append(f"<div class=kind><b>{kind.upper()}</b>")
            for it in sorted(items, key=lambda x: x["key"]):
                val = f"  <span class=v>{_esc(it['value'])}</span>" if it["value"] else ""
                parts.append(f"<div class=row><span class=k>{_esc(it['key'])}</span>{val}</div>")
            parts.append("</div>")

        serie = trend.get(target, [])
        total_periodo = sum(d["total"] for d in serie)
        parts.append(f"<div class=trend><b>TENDÊNCIA · {trend_days}d</b>")
        if total_periodo:
            parts.append(_trend_svg(serie, trend_days))
            parts.append(
                "<div class=legend>"
                f"<i style='background:{_TREND_ADD}'></i>added"
                f"<i style='background:{_TREND_CHG}'></i>changed"
                f"<i style='background:{_TREND_REM}'></i>removed"
                f" · {total_periodo} evento(s) no período</div>"
            )
        else:
            parts.append(f"<div class=empty>sem eventos nos últimos {trend_days} dias.</div>")
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
