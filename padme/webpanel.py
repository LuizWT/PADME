"""Painel web read-only da superfície de ataque — visão de monitoração (ZABBIX-like).

Serve uma página HTML (só stdlib, sem dependências) que lê o padme.db e mostra,
num relance: um resumo global, um painel de PROBLEMAS abertos (takeover, cert
expirando, wildcard, coleta parcial) priorizado por severidade, e um cartão por
alvo com saúde da coleta, KPIs da superfície, tendência e últimos eventos.

Só leitura — não altera nada. Bind em localhost por padrão.

Design: paleta escura validada (status good/warning/serious/critical com
chip = ponto + rótulo, nunca cor sozinha), tipografia de sistema, hairlines,
`tabular-nums` nos números. Renderização server-side; atualiza sozinho (meta).
"""

from __future__ import annotations

import html
import http.server
import socketserver
from datetime import datetime

from .levels import Level, severity
from .storage import Storage

_KIND_ORDER = ["takeover", "cert_expiry", "wildcard", "subdomain", "port", "http", "tls", "dns"]
_KIND_LABEL = {
    "takeover": "TAKEOVER", "cert_expiry": "CERT", "wildcard": "WILDCARD",
    "subdomain": "SUBDOMAIN", "port": "PORT", "http": "HTTP", "tls": "TLS", "dns": "DNS",
}
_ARROW = {"added": "+", "removed": "−", "changed": "~"}

# ── cores (dataviz — validadas p/ superfície escura) ────────────────────────
_TREND_ADD, _TREND_CHG, _TREND_REM = "#199e70", "#c98500", "#e66767"

_CSS = """
:root{
  color-scheme:dark;
  --plane:#0d0d0d; --surface:#1a1a19; --inset:#111110;
  --ink:#ffffff; --ink2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --line:#383835; --border:rgba(255,255,255,.10);
  --ok:#0ca30c; --warn:#fab219; --serious:#ec835a; --crit:#d03b3b; --info:#3987e5;
  --add:#199e70; --chg:#c98500; --rem:#e66767;
  --r:12px;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--plane);color:var(--ink2);font:14px/1.55 var(--sans)}
a{color:inherit}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 40px}
.tabnum{font-variant-numeric:tabular-nums}

/* topbar */
header{position:sticky;top:0;z-index:5;background:rgba(13,13,13,.86);
  backdrop-filter:blur(8px);border-bottom:1px solid var(--border)}
.top{max-width:1180px;margin:0 auto;padding:14px 16px;display:flex;align-items:baseline;
  gap:12px;flex-wrap:wrap}
.brand{font-weight:700;letter-spacing:.02em;color:var(--ink);font-size:17px}
.brand small{font-weight:500;color:var(--muted);font-size:12px;letter-spacing:.04em;margin-left:8px}
.top .spacer{flex:1}
.pill{font-size:11px;color:var(--muted);border:1px solid var(--border);border-radius:999px;
  padding:3px 10px;letter-spacing:.03em}
.pill b{color:var(--ink2);font-weight:600}

/* section title */
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);
  margin:26px 2px 10px;font-weight:600}

/* KPI row */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:10px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  padding:14px 16px;position:relative;overflow:hidden}
.kpi .n{font-size:30px;font-weight:650;color:var(--ink);line-height:1;font-variant-numeric:tabular-nums}
.kpi .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:7px}
.kpi .s{font-size:11px;color:var(--ink2);margin-top:3px}
.kpi.accent::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--info)}
.kpi.ok::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--ok)}
.kpi.crit::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--crit)}
.kpi.warn::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--warn)}
.kpi.crit .n{color:var(--crit)} .kpi.warn .n{color:var(--warn)} .kpi.ok .n{color:var(--ok)}

/* status chip: ponto + rótulo (nunca cor sozinha) */
.chip{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:600;
  letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
.chip .dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
.s-crit{color:#f2a3a3}.s-crit .dot{background:var(--crit)}
.s-serious{color:#f2c1ab}.s-serious .dot{background:var(--serious)}
.s-warn{color:#f4d68a}.s-warn .dot{background:var(--warn)}
.s-info{color:#a9c9f2}.s-info .dot{background:var(--info)}
.s-ok{color:#8fd48f}.s-ok .dot{background:var(--ok)}
.s-muted{color:var(--muted)}.s-muted .dot{background:var(--muted)}

/* problems panel */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.prow{display:grid;grid-template-columns:120px 1fr auto;gap:12px;align-items:center;
  padding:11px 16px;border-top:1px solid var(--border)}
.prow:first-child{border-top:0}
.prow .who{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}
.prow .det{font-size:12px;color:var(--ink2);word-break:break-all}
.prow .tgt{font-size:11px;color:var(--muted);font-family:var(--mono);text-align:right}
.calm{padding:16px;display:flex;align-items:center;gap:10px;color:var(--ink2)}

/* host card */
.host{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);
  margin-top:12px;overflow:hidden;scroll-margin-top:70px}
.host>h2{margin:0;padding:13px 16px;display:flex;align-items:center;gap:10px;
  border-bottom:1px solid var(--border);font-size:15px;color:var(--ink);font-weight:650}
.host>h2 .name{font-family:var(--mono);letter-spacing:0}
.host>h2 .count{margin-left:auto;font-size:11px;color:var(--muted);font-weight:500;letter-spacing:.04em}
.health{display:flex;flex-wrap:wrap;gap:6px 16px;padding:9px 16px;border-bottom:1px solid var(--border);
  font-size:11.5px;color:var(--muted)}
.health b{color:var(--ink2);font-weight:600}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(96px,1fr));gap:8px;padding:14px 16px}
.tile{background:var(--inset);border:1px solid var(--border);border-radius:10px;padding:10px 12px}
.tile .num{font-size:20px;font-weight:650;color:var(--ink);line-height:1.05;font-variant-numeric:tabular-nums}
.tile .lab{font-size:10px;letter-spacing:.05em;color:var(--muted);margin-top:3px;text-transform:uppercase}
.tile .sub{font-size:10px;color:var(--ink2);margin-top:2px}
.tile.crit{border-color:rgba(208,59,59,.5)}.tile.crit .num{color:var(--crit)}
.tile.warn{border-color:rgba(250,178,25,.45)}.tile.warn .num{color:var(--warn)}

details.kinds{border-top:1px solid var(--border)}
details.kinds>summary{list-style:none;cursor:pointer;padding:10px 16px;font-size:11px;
  letter-spacing:.1em;text-transform:uppercase;color:var(--muted);user-select:none}
details.kinds>summary::-webkit-details-marker{display:none}
details.kinds>summary::before{content:"▸ ";color:var(--muted)}
details.kinds[open]>summary::before{content:"▾ "}
.kind{padding:6px 16px 10px}
.kind b{color:var(--info);font-size:11px;letter-spacing:.06em}
.row{padding:2px 0 2px 12px;white-space:pre-wrap;word-break:break-all;font-family:var(--mono);font-size:12.5px}
.row .k{color:var(--ink)} .row .v{color:var(--muted)}

.trend{padding:12px 16px;border-top:1px solid var(--border)}
.trend .hd{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.trend b{color:var(--info);font-size:11px;letter-spacing:.06em;text-transform:uppercase}
.trend .net{font-size:11px;color:var(--muted)}
.trend .net b2{color:var(--ink2)}
.trend svg{width:100%;height:auto;display:block;margin-top:8px}
.legend{color:var(--muted);font-size:11px;margin-top:5px}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin:0 5px 0 12px;vertical-align:middle}

.events{padding:8px 16px 14px;border-top:1px solid var(--border)}
.events .line{padding:3px 0;display:flex;gap:8px;align-items:baseline;font-size:12.5px;border-top:1px solid rgba(255,255,255,.04)}
.events .line:first-of-type{border-top:0}
.events .when{color:var(--muted);font-family:var(--mono);font-size:11px;white-space:nowrap}
.events .body{font-family:var(--mono);word-break:break-all}
.events .add .mk{color:var(--add)} .events .rem .mk{color:var(--rem)} .events .chg .mk{color:var(--chg)}
.events .mk{font-weight:700}

.empty{color:var(--muted);padding:16px}
.banner{background:#2a1414;border:1px solid var(--crit);color:#f2a3a3;border-radius:10px;
  padding:11px 14px;margin:16px 0 0;font-size:12.5px}
footer{color:var(--muted);font-size:11px;margin-top:30px;text-align:center;padding-top:16px;
  border-top:1px solid var(--border)}
@media(max-width:560px){.prow{grid-template-columns:1fr;gap:4px}.prow .tgt{text-align:left}}
"""


def _esc(s) -> str:
    return html.escape(str(s or ""))


def _ts_human(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%d/%m %H:%M")
    except Exception:
        return "—"


# severidade (Level) -> (classe de status, rótulo curto)
_SEV = {
    Level.CRITICAL: ("s-crit", "crítico"),
    Level.HIGH: ("s-serious", "alto"),
    Level.MEDIUM: ("s-warn", "médio"),
    Level.LOW: ("s-info", "baixo"),
    Level.DEBUG: ("s-muted", "debug"),
}


def _chip(cls: str, label: str) -> str:
    return f"<span class='chip {cls}'><span class=dot></span>{_esc(label)}</span>"


# ── problemas abertos (agregado, priorizado) ────────────────────────────────
def _collect_problems(by_target: dict, meta: dict) -> list[dict]:
    """Varre o estado atual e devolve os problemas abertos, mais grave primeiro."""
    prob: list[dict] = []
    for target, kinds in by_target.items():
        for it in kinds.get("takeover", []):
            prob.append({"rank": 4, "cls": "s-crit", "sev": "crítico", "kind": "TAKEOVER",
                         "who": it["key"], "det": it["value"], "tgt": target})
        for it in kinds.get("cert_expiry", []):
            expired = "EXPIRAD" in (it["value"] or "").upper()
            prob.append({"rank": 4 if expired else 3,
                         "cls": "s-crit" if expired else "s-serious",
                         "sev": "expirado" if expired else "expira",
                         "kind": "CERT", "who": it["key"], "det": it["value"], "tgt": target})
        for it in kinds.get("wildcard", []):
            prob.append({"rank": 2, "cls": "s-warn", "sev": "atenção", "kind": "WILDCARD",
                         "who": it["key"], "det": f"catch-all {it['value']}", "tgt": target})
    # coleta parcial por alvo (não é da superfície, mas é um problema operacional)
    for target, m in meta.items():
        if m and m.get("last_partial"):
            n = m.get("last_error_count") or "?"
            prob.append({"rank": 2, "cls": "s-warn", "sev": "atenção", "kind": "COLETA",
                         "who": target, "det": f"coleta parcial — {n} erro(s) de collector", "tgt": target})
    prob.sort(key=lambda p: (-p["rank"], p["tgt"], p["who"]))
    return prob


def _problems_panel(problems: list[dict]) -> str:
    if not problems:
        return ("<div class=panel><div class=calm>"
                + _chip("s-ok", "tudo ok")
                + "<span>nenhum problema aberto na superfície monitorada.</span></div></div>")
    rows = []
    for p in problems:
        rows.append(
            "<div class=prow>"
            f"<div>{_chip(p['cls'], p['sev'])}</div>"
            f"<div><div class=who>{_esc(p['kind'])} · {_esc(p['who'])}</div>"
            f"<div class=det>{_esc(p['det'])}</div></div>"
            f"<div class=tgt>{_esc(p['tgt'])}</div>"
            "</div>"
        )
    return "<div class=panel>" + "".join(rows) + "</div>"


# ── KPIs globais ────────────────────────────────────────────────────────────
def _kpi(n, label: str, sub: str = "", cls: str = "") -> str:
    sub_html = f"<div class=s>{_esc(sub)}</div>" if sub else ""
    return (f"<div class='kpi {cls}'><div class=n>{_esc(n)}</div>"
            f"<div class=l>{_esc(label)}</div>{sub_html}</div>")


def _global_kpis(by_target: dict, meta: dict, problems: list[dict], n_targets: int) -> str:
    assets = sum(len(v) for kinds in by_target.values() for v in kinds.values())
    crit = sum(1 for p in problems if p["cls"] in ("s-crit", "s-serious"))
    partial = sum(1 for m in meta.values() if m and m.get("last_partial"))
    ok_hosts = sum(1 for t in by_target if not (meta.get(t) or {}).get("last_partial"))
    prob_cls = "crit" if crit else ("warn" if problems else "ok")
    tiles = [
        _kpi(n_targets, "alvos", f"{len(by_target)} com dados", cls="accent"),
        _kpi(assets, "ativos observados", "subdomínios, portas, serviços…"),
        _kpi(len(problems), "problemas abertos",
             f"{crit} de alta gravidade" if problems else "superfície limpa", cls=prob_cls),
        _kpi(f"{ok_hosts}/{len(by_target) or 0}", "coleta saudável",
             f"{partial} parcial(is)" if partial else "sem coleta parcial",
             cls=("warn" if partial else "ok")),
    ]
    return "<div class=kpis>" + "".join(tiles) + "</div>"


# ── stat tiles por alvo ─────────────────────────────────────────────────────
def _tile(num, lab: str, sub: str = "", cls: str = "") -> str:
    sub_html = f"<div class=sub>{_esc(sub)}</div>" if sub else ""
    return (f"<div class='tile {cls}'><div class=num>{_esc(num)}</div>"
            f"<div class=lab>{_esc(lab)}</div>{sub_html}</div>")


def _stat_tiles(kinds: dict) -> str:
    subs = kinds.get("subdomain", [])
    live = sum(1 for s in subs if s["value"] == "live")
    quiet = sum(1 for s in subs if s["value"] == "quiet")
    tiles = [
        _tile(len(subs), "subdomínios", f"{live} live · {quiet} quiet" if subs else ""),
        _tile(len(kinds.get("http", [])), "serviços http"),
        _tile(len(kinds.get("port", [])), "portas abertas"),
        _tile(len(kinds.get("tls", [])), "certificados"),
    ]
    if kinds.get("takeover"):
        tiles.append(_tile(len(kinds["takeover"]), "takeover", "crítico", cls="crit"))
    if kinds.get("cert_expiry"):
        tiles.append(_tile(len(kinds["cert_expiry"]), "cert expirando", cls="warn"))
    if kinds.get("wildcard"):
        tiles.append(_tile(len(kinds["wildcard"]), "wildcard dns", cls="warn"))
    return "<div class=tiles>" + "".join(tiles) + "</div>"


# ── tendência (barras empilhadas add/chg/rem por dia) ───────────────────────
def _trend_svg(series: list[dict], days: int) -> str:
    W, H = 720.0, 132.0
    pad_l, pad_r, pad_t, pad_b = 26.0, 8.0, 10.0, 20.0
    plot_w, plot_h = W - pad_l - pad_r, H - pad_t - pad_b
    base_y = pad_t + plot_h
    max_total = max((d["total"] for d in series), default=0)
    parts = [f'<svg viewBox="0 0 {W:.0f} {H:.0f}" role="img" '
             f'aria-label="eventos por dia ({days}d)" preserveAspectRatio="none">']
    parts.append(f'<line x1="{pad_l}" y1="{base_y:.1f}" x2="{W - pad_r:.1f}" y2="{base_y:.1f}" '
                 'stroke="#383835" stroke-width="1"/>')
    if max_total > 0:
        parts.append(f'<text x="{pad_l - 4:.1f}" y="{pad_t + 4:.1f}" text-anchor="end" '
                     f'font-size="9" fill="#898781">{max_total}</text>')
    n = len(series)
    slot = plot_w / n if n else plot_w
    bar_w = max(1.0, slot - 2.0)
    scale = (plot_h / max_total) if max_total > 0 else 0.0

    def seg(x, yb, h, color):
        drawn = h - 2 if h > 2 else h
        return (f'<rect x="{x:.1f}" y="{yb - drawn:.1f}" width="{bar_w:.1f}" '
                f'height="{drawn:.1f}" fill="{color}" rx="1.5"/>')

    for i, d in enumerate(series):
        x = pad_l + i * slot + (slot - bar_w) / 2
        yb = base_y
        title = f'{d["day"]}: +{d["added"]} · ~{d["changed"]} · −{d["removed"]}'
        cells = []
        for key, color in (("added", _TREND_ADD), ("changed", _TREND_CHG), ("removed", _TREND_REM)):
            h = d[key] * scale
            if h > 0:
                cells.append(seg(x, yb, h, color))
                yb -= h
        parts.append(f'<g><title>{_esc(title)}</title>{"".join(cells)}</g>')
    if n:
        for idx in sorted({0, n // 2, n - 1}):
            label = series[idx]["day"][5:]
            cx = pad_l + idx * slot + slot / 2
            anchor = "start" if idx == 0 else ("end" if idx == n - 1 else "middle")
            parts.append(f'<text x="{cx:.1f}" y="{H - 6:.1f}" text-anchor="{anchor}" '
                         f'font-size="9" fill="#898781">{label}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _trend(serie: list[dict], days: int) -> str:
    total = sum(d["total"] for d in serie)
    added = sum(d["added"] for d in serie)
    removed = sum(d["removed"] for d in serie)
    net = added - removed
    net_s = f"+{net}" if net > 0 else str(net)
    out = ['<div class=trend><div class=hd>'
           f'<b>tendência · {days}d</b>']
    if total:
        out.append(f'<span class=net>líquido <b2>{net_s}</b2> · +{added}/−{removed} · {total} evento(s)</span>')
    out.append('</div>')
    if total:
        out.append(_trend_svg(serie, days))
        out.append('<div class=legend>'
                   f'<i style="background:{_TREND_ADD}"></i>added'
                   f'<i style="background:{_TREND_CHG}"></i>changed'
                   f'<i style="background:{_TREND_REM}"></i>removed</div>')
    else:
        out.append(f'<div class=empty>sem eventos nos últimos {days} dias.</div>')
    out.append('</div>')
    return "".join(out)


# ── saúde da coleta por alvo ────────────────────────────────────────────────
def _health(meta: dict | None) -> str:
    if not meta:
        return "<div class=health>sem scan registrado ainda.</div>"
    errs = meta.get("last_error_count")
    partial = bool(meta.get("last_partial"))
    dur = meta.get("last_duration_ms")
    ok = not partial and (errs == 0 or errs is None)
    chip = _chip("s-ok", "dados completos") if ok else _chip("s-warn", "dados parciais")
    bits = [chip,
            f"último scan: <b>{_ts_human(meta.get('last_scan_at'))}</b>",
            f"scan OK: <b>{_ts_human(meta.get('last_success_at'))}</b>"]
    if errs is not None:
        bits.append(f"erros: <b>{errs}</b>")
    if dur is not None:
        bits.append(f"duração: <b>{dur} ms</b>")
    return "<div class=health>" + " · ".join(bits) + "</div>"


def _host_status(kinds: dict, meta: dict | None) -> str:
    if kinds.get("takeover"):
        return _chip("s-crit", "takeover")
    if kinds.get("cert_expiry"):
        return _chip("s-serious", "cert")
    if (meta or {}).get("last_partial") or kinds.get("wildcard"):
        return _chip("s-warn", "atenção")
    if not kinds:
        return _chip("s-muted", "sem dados")
    return _chip("s-ok", "ok")


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower())


def _host_card(target: str, kinds: dict, events: list, serie: list[dict],
               meta: dict | None, trend_days: int) -> str:
    total = sum(len(v) for v in kinds.values())
    parts = [f"<section class=host id='h-{_slug(target)}'>",
             f"<h2>{_host_status(kinds, meta)}<span class=name>{_esc(target)}</span>"
             f"<span class=count>{total} ativo(s)</span></h2>",
             _health(meta)]
    if not kinds:
        parts.append("<div class=empty>sem baseline ainda — rode um scan para este alvo.</div>")
    else:
        parts.append(_stat_tiles(kinds))
        # detalhe completo por categoria, recolhido por padrão (denso mas opcional)
        det = ['<details class=kinds><summary>ativos por categoria</summary>']
        for kind in _KIND_ORDER:
            items = kinds.get(kind)
            if not items:
                continue
            det.append(f"<div class=kind><b>{_KIND_LABEL[kind]}</b>")
            for it in sorted(items, key=lambda x: x["key"]):
                v = f"  <span class=v>{_esc(it['value'])}</span>" if it["value"] else ""
                det.append(f"<div class=row><span class=k>{_esc(it['key'])}</span>{v}</div>")
            det.append("</div>")
        det.append("</details>")
        parts.append("".join(det))
    parts.append(_trend(serie, trend_days))
    if events:
        ev = ['<div class=events>']
        for e in events:
            cls = {"added": "add", "removed": "rem", "changed": "chg"}[e.event_type.value]
            val = e.new_value if e.event_type.value != "removed" else e.old_value
            when = (e.detected_at or "")[5:16].replace("T", " ")
            scls, slabel = _SEV.get(severity(e), ("s-muted", ""))
            ev.append(
                f"<div class='line {cls}'>"
                f"<span class=when>{_esc(when)}</span>"
                f"{_chip(scls, slabel)}"
                f"<span class=body><span class=mk>{_ARROW[e.event_type.value]}</span> "
                f"[{e.kind.value}] {_esc(e.key)} {_esc(val)}</span></div>"
            )
        ev.append("</div>")
        parts.append("".join(ev))
    parts.append("</section>")
    return "".join(parts)


def _render(cfg, exposed: bool = False) -> str:
    trend_days = 30
    storage = Storage(cfg.db_path)
    try:
        rows = storage.all_state()  # TODOS os alvos do banco (não esconde dados)
        db_targets = sorted({r["target"] for r in rows})
        targets = sorted(set(cfg.targets) | set(db_targets))
        events = {t: storage.recent_events(t, 20) for t in targets}
        trend = {t: storage.events_per_day(t, trend_days) for t in targets}
        meta = {t: storage.target_meta(t) for t in targets}
    finally:
        storage.close()

    by_target: dict[str, dict[str, list]] = {t: {} for t in db_targets}
    for r in rows:
        by_target[r["target"]].setdefault(r["kind"], []).append(r)

    problems = _collect_problems(by_target, meta)

    parts = [
        "<!doctype html><html lang=pt-br><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        "<meta http-equiv=refresh content=30>",
        "<title>Padmé — superfície</title><style>", _CSS, "</style></head><body>",
        "<header><div class=top>",
        "<div class=brand>🛰️ PADMÉ<small>attack surface monitor</small></div>",
        "<div class=spacer></div>",
        f"<span class=pill>alvos <b>{len(targets)}</b></span>",
        f"<span class=pill>atualizado <b>{datetime.now():%d/%m %H:%M:%S}</b></span>",
        "<span class=pill>auto <b>30s</b></span>",
        "</div></header><div class=wrap>",
    ]
    if exposed:
        parts.append("<div class=banner>⚠️ Painel exposto fora de localhost e SEM autenticação. "
                     "Qualquer um com acesso à rede vê sua superfície de ataque.</div>")

    parts.append("<div class=eyebrow>visão geral</div>")
    parts.append(_global_kpis(by_target, meta, problems, len(targets)))

    parts.append(f"<div class=eyebrow>problemas abertos · {len(problems)}</div>")
    parts.append(_problems_panel(problems))

    parts.append("<div class=eyebrow>alvos</div>")
    if not targets:
        parts.append("<div class=panel><div class=empty>nenhum alvo ainda — rode "
                     "<code>padme scan</code> ou <code>padme monitor</code>.</div></div>")
    for target in targets:
        parts.append(_host_card(target, by_target.get(target, {}), events.get(target, []),
                                trend.get(target, []), meta.get(target), trend_days))

    parts.append("<footer>Padmé · painel read-only · lê o padme.db, não altera nada</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


def serve(cfg, host: str = "127.0.0.1", port: int = 8787, exposed: bool = False) -> None:
    page_cfg = cfg

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = _render(page_cfg, exposed=exposed).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Server((host, port), Handler) as httpd:
        print(f"Painel em http://{host}:{port}  (Ctrl+C para parar)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nEncerrando painel.")
