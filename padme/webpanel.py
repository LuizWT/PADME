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

import base64
import csv
import hmac
import html
import http.server
import io
import json
import socketserver
import threading
import urllib.parse
from datetime import datetime
from pathlib import Path

from .evidence import evidence_of
from .merge import merge_exports
from .panel_assets import _CSS, _TREND_ADD, _TREND_CHG, _TREND_JS, _TREND_REM
from .panel_metrics import (
    _collect_problems,
    _collector_reliability,
    _explainability,
    _prioritize_events,
)
from .risk import Level
from .storage import Storage, StorageOutdated

_KIND_ORDER = ["takeover", "cert_expiry", "ns", "mailsec", "wildcard",
               "subdomain", "port", "http", "httpsec", "favicon", "tls", "dns"]
_KIND_LABEL = {
    "takeover": "TAKEOVER", "cert_expiry": "CERT", "ns": "NS", "mailsec": "E-MAIL",
    "wildcard": "WILDCARD", "subdomain": "SUBDOMAIN", "port": "PORT",
    "http": "HTTP", "httpsec": "HEADERS", "favicon": "FAVICON", "tls": "TLS", "dns": "DNS",
}
_ARROW = {"added": "+", "removed": "−", "changed": "~"}

def _esc(s) -> str:
    # NÃO use `s or ""`: 0 e False são válidos e viram "" assim (o tile de
    # "portas abertas" com contagem 0 ficava EM BRANCO). Só None é vazio.
    return html.escape("" if s is None else str(s))


def _ts_human(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%d/%m %H:%M")
    except Exception:
        return "—"


def _changes_html(changes: dict | None) -> str:
    """Detalhe do diff semântico de um CHANGED: campo: old → new."""
    if not changes:
        return ""
    def fmt(v):  # conjuntos (DNS, SANs do TLS) em texto, não repr de lista
        return ", ".join(map(str, v)) if isinstance(v, list) else v

    bits = [f"{_esc(f)}: {_esc(fmt(ch.get('old')))} → {_esc(fmt(ch.get('new')))}"
            for f, ch in changes.items()]
    return "<span class=chgdet>" + " · ".join(bits) + "</span>"


def _proof_html(e, value: str | None) -> str:
    """Evidência normalizada da observação (§6.3), inline e discreta. Só para
    ADDED/CHANGED — um REMOVED não reafirma uma observação atual. O tipo fica
    visível; os fatos completos no tooltip."""
    if e.event_type.value == "removed":
        return ""
    ev = evidence_of(e.kind, e.key, value, e.metadata)
    if not ev:
        return ""
    typ = ev.get("type", "")
    facts = " · ".join(f"{k}={v}" for k, v in ev.items() if k != "type")
    full = f"{typ} — {facts}" if facts else typ
    return f"<span class=proof title='{_esc(full)}'>prova: {_esc(typ)}</span>"


def _port_fp(metadata: dict | None) -> str:
    """Badges de service/product/version de uma porta (do metadata do record).
    O que hoje só ia na evidência/webhook agora aparece na linha do ativo."""
    md = metadata or {}
    svc = md.get("service")
    product = md.get("product")
    version = md.get("version")
    if not (svc or product):
        return ""
    bits = []
    if svc:
        bits.append(f"<span class=svc>{_esc(svc)}</span>")
    if product:
        pv = f"{product} {version}" if version else product
        bits.append(f"<span class=prod>{_esc(pv)}</span>")
    return f"<span class=fp>{''.join(bits)}</span>"


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
def _problems_panel(problems: list[dict]) -> str:
    if not problems:
        return ("<div class=panel><div class=calm>"
                + _chip("s-ok", "tudo ok")
                + "<span>nenhum problema aberto na superfície monitorada.</span></div></div>")
    rows = []
    for p in problems:
        proof = p.get("evidence")
        proof_html = f"<div class=proof>prova: {_esc(proof)}</div>" if proof else ""
        rows.append(
            "<div class=prow>"
            f"<div>{_chip(p['cls'], p['sev'])}</div>"
            f"<div><div class=who>{_esc(p['kind'])} · {_esc(p['who'])}</div>"
            f"<div class=det>{_esc(p['det'])}</div>{proof_html}</div>"
            f"<div class=tgt>{_esc(p['tgt'])}</div>"
            "</div>"
        )
    return "<div class=panel>" + "".join(rows) + "</div>"


# ── KPIs globais ────────────────────────────────────────────────────────────
def _kpi(n, label: str, sub: str = "", cls: str = "") -> str:
    sub_html = f"<div class=s>{_esc(sub)}</div>" if sub else ""
    return (f"<div class='kpi {cls}'><div class=n>{_esc(n)}</div>"
            f"<div class=l>{_esc(label)}</div>{sub_html}</div>")


def _global_kpis(by_target: dict, meta: dict, problems: list[dict], n_targets: int,
                 explain: dict | None = None) -> str:
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
    rel = _collector_reliability(meta)
    if rel:  # §27: confiabilidade dos collectors (só quando há saúde registrada)
        pct = rel["pct"]
        cls = "crit" if rel["has_error"] else ("warn" if rel["degraded"] else "ok")
        sub = (f"{rel['ok']}/{rel['total']} observações ok"
               if not rel["degraded"] else
               f"{rel['ok']}/{rel['total']} ok · degradado: " + ", ".join(rel["degraded"]))
        tiles.append(_kpi(f"{pct}%", "collectors confiáveis", sub, cls=cls))
    if explain:  # §27: só aparece quando há evento HIGH/CRITICAL recente p/ medir
        pct = explain["pct"]
        cls = "ok" if pct == 100 else ("warn" if pct >= 50 else "crit")
        sub = (f"{explain['explained']}/{explain['high']} HIGH+ com razão+proveniência+evidência"
               if pct == 100 else
               f"{explain['explained']}/{explain['high']} HIGH+ · falta "
               + ", ".join(explain["missing"]))
        tiles.append(_kpi(f"{pct}%", "alertas explicáveis", sub, cls=cls))
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
    out = [f'<div class=trend data-days="{days}"><div class=hd>'
           f'<b>tendência · {days}d</b><span class=lghint>sem registros DNS</span>']
    if total:
        out.append(f'<span class=net>líquido <b2>{net_s}</b2> · +{added}/−{removed} · {total} evento(s)</span>')
    out.append('</div>')
    if total:
        # SVG estático = fallback sem-JS; o JS redesenha e as tags viram filtros.
        out.append(f'<div class=chart>{_trend_svg(serie, days)}</div>')
        out.append(
            '<div class=legend>'
            f'<button type=button class="lg on" data-t=added><i style="background:{_TREND_ADD}"></i>added</button>'
            f'<button type=button class="lg on" data-t=changed><i style="background:{_TREND_CHG}"></i>changed</button>'
            f'<button type=button class="lg on" data-t=removed><i style="background:{_TREND_REM}"></i>removed</button>'
            '<span class=lghint>clique p/ filtrar</span></div>')
        out.append('<script type="application/json" class=tdata>'
                   + json.dumps(serie, ensure_ascii=False) + '</script>')
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
    inc = meta.get("last_inconclusive") or 0
    ok = not partial and (errs == 0 or errs is None)
    # parcial = algum collector QUEBROU (erro). Sem resposta (timeout) é outra
    # coisa: o estado foi preservado, então a coleta segue ok, mas o número
    # aparece — não esconde a incerteza nem pinta o alvo de amarelo à toa.
    if not ok:
        chip = _chip("s-warn", "dados parciais")
    elif inc:
        chip = _chip("s-ok", f"coleta ok · {inc} inconclusivo{'s' if inc != 1 else ''}")
    else:
        chip = _chip("s-ok", "dados completos")
    bits = [chip,
            f"último scan: <b>{_ts_human(meta.get('last_scan_at'))}</b>",
            f"scan OK: <b>{_ts_human(meta.get('last_success_at'))}</b>"]
    if errs is not None:
        bits.append(f"erros: <b>{errs}</b>")
    if dur is not None:
        bits.append(f"duração: <b>{dur} ms</b>")
    out = "<div class=health>" + " · ".join(bits) + "</div>"
    # saúde POR collector (DNS ok / PORTS partial / CT error) — §7 do roadmap
    ch = meta.get("collectors_health") or {}
    if ch:
        _cls = {"ok": "s-ok", "partial": "s-warn", "error": "s-crit"}
        chips = "".join(
            f"<span class=chp>{_esc(name)} {_chip(_cls.get(v.get('status'), 's-muted'), v.get('status', '?'))}</span>"
            for name, v in sorted(ch.items()))
        out += f"<div class=collhealth>{chips}</div>"
    return out


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
        # detalhe completo por categoria. `data-persist`: a JS lembra aberto/
        # fechado entre os auto-refreshes de 30s (senão recolhia sozinho).
        det = [f"<details class=kinds data-persist='k-{_slug(target)}'>"
               "<summary>ativos por categoria</summary>",
               "<input class=kfilter type=search autocomplete=off "
               "placeholder='filtrar (host, porta, kind, valor)…' "
               "aria-label='filtrar ativos'>"]
        for kind in _KIND_ORDER:
            items = kinds.get(kind)
            if not items:
                continue
            # data-kind p/ a busca casar também o nome da categoria (ex.: 'port')
            det.append(f"<div class=kind data-kind='{kind}'><b>{_KIND_LABEL[kind]}</b>")
            for it in sorted(items, key=lambda x: x["key"]):
                v = f"  <span class=v>{_esc(it['value'])}</span>" if it["value"] else ""
                fp = _port_fp(it.get("metadata")) if kind == "port" else ""
                det.append(f"<div class=row><span class=k>{_esc(it['key'])}</span>{v}{fp}</div>")
            det.append("</div>")
        det.append("</details>")
        parts.append("".join(det))
    parts.append(_trend(serie, trend_days))
    if events:
        ev = ['<div class=events>']
        for e, risk in _prioritize_events(events):
            cls = {"added": "add", "removed": "rem", "changed": "chg"}[e.event_type.value]
            val = e.new_value if e.event_type.value != "removed" else e.old_value
            when = (e.detected_at or "")[5:16].replace("T", " ")
            scls, slabel = _SEV.get(risk.level, ("s-muted", ""))
            labels = risk.reason_labels()
            why = ""
            if risk.level > risk.base and labels:   # só destaca quando o contexto elevou
                extra = f" +{len(labels) - 1}" if len(labels) > 1 else ""
                why = (f"<span class=why title='{_esc(' · '.join(labels))}'>▲ "
                       f"{_esc(labels[0])}{extra}</span>")
            conf = ("" if risk.confidence.name == "CONFIRMED"
                    else f"<span class=conf>conf: {risk.confidence.name.lower()}</span>")
            changes = _changes_html(e.metadata.get("_changes")) if e.metadata else ""
            proof = _proof_html(e, val)
            ev.append(
                f"<div class='line {cls}'>"
                f"<span class=when>{_esc(when)}</span>"
                f"{_chip(scls, slabel)}"
                f"<span class=body><span class=mk>{_ARROW[e.event_type.value]}</span> "
                f"[{e.kind.value}] {_esc(e.key)} {_esc(val)}{why}{conf}{proof}{changes}</span></div>"
            )
        ev.append("</div>")
        parts.append("".join(ev))
    parts.append("</section>")
    return "".join(parts)


def _filter_form(all_targets: list[str], only: str | None) -> str:
    """Dropdown com digitação + autocomplete (datalist nativo). Submit via GET
    navega para /?target=... — funciona sem JS."""
    opts = "".join(f'<option value="{_esc(t)}">' for t in all_targets)
    clear = '<a class=fclear href="/">limpar</a>' if only else ""
    return (
        '<form class=filterform method=get action="/">'
        f'<input class=finput name=target list=targetlist autocomplete=off '
        f'placeholder="filtrar por domínio…" value="{_esc(only or "")}">'
        f'<datalist id=targetlist>{opts}</datalist>'
        '<button class=fbtn type=submit>filtrar</button>'
        f'{clear}</form>'
    )


def _export_actions(only: str | None) -> str:
    q = f"&target={urllib.parse.quote(only)}" if only else ""
    return (
        '<span class=exports>exportar:'
        f'<a class=xbtn href="/export?fmt=json{q}">JSON</a>'
        f'<a class=xbtn href="/export?fmt=csv{q}">CSV</a></span>'
    )


def _open_ro(cfg) -> Storage | None:
    """Abre o banco SÓ PARA LEITURA (o painel nunca escreve/migra). Banco que
    ainda não existe -> None (página vazia, sem criar arquivo)."""
    try:
        return Storage(cfg.db_path, readonly=True)
    except FileNotFoundError:
        return None


def _export_rows(cfg, only: str | None) -> list[dict]:
    storage = _open_ro(cfg)
    if storage is None:
        return []
    try:
        rows = storage.all_state()
    finally:
        storage.close()
    if only:
        exact = [r for r in rows if r["target"] == only]
        rows = exact or [r for r in rows if only in r["target"]]
    return [{
        "source": cfg.source, "target": r["target"], "kind": r["kind"], "key": r["key"],
        "value": r["value"],
        "first_seen": _ts_human(r["first_seen"]), "last_seen": _ts_human(r["last_seen"]),
        "metadata": r.get("metadata") or {},
    } for r in rows]


def render_export(cfg, only: str | None, fmt: str) -> tuple[str, str]:
    """Devolve (corpo, content_type) do export — mesmos campos do `padme export`."""
    recs = _export_rows(cfg, only)
    if fmt == "csv":
        buf = io.StringIO()
        cols = ["source", "target", "kind", "key", "value", "first_seen", "last_seen", "metadata"]
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for r in recs:
            w.writerow({**r, "metadata": json.dumps(r["metadata"], ensure_ascii=False)})
        return buf.getvalue(), "text/csv; charset=utf-8"
    return json.dumps(recs, indent=2, ensure_ascii=False), "application/json; charset=utf-8"


# ── multi-vantage (consolida exports de várias fontes; reusa padme merge) ────
def _vantage_exports(cfg) -> tuple[list[list[dict]], list[str]]:
    """Junta o estado LOCAL (source=cfg.source) + cada .json em web.vantage_dir.
    Devolve (exports, avisos). A máquina do painel é um ponto de observação; os
    outros vêm de arquivos exportados por `padme export`. Arquivo inválido é
    PULADO com aviso — nunca derruba a página."""
    exports: list[list[dict]] = [_export_rows(cfg, None)]  # já traz source=cfg.source
    warnings: list[str] = []
    raw = cfg.web.vantage_dir
    if not raw:
        return exports, warnings
    d = Path(raw)
    if not d.is_dir():
        warnings.append(f"vantage_dir não encontrado: {raw}")
        return exports, warnings
    for fp in sorted(d.glob("*.json")):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"{fp.name}: inválido ({type(exc).__name__})")
            continue
        rows = data if isinstance(data, list) else data.get("rows")
        if not isinstance(rows, list):
            warnings.append(f"{fp.name}: formato inesperado (esperava lista de linhas)")
            continue
        exports.append(rows)
    return exports, warnings


def _vantage_values(a: dict, sources: list[str]) -> str:
    """Valor observado por fonte (— = ausente)."""
    vals = a.get("values", {})
    bits = []
    for s in sources:
        v = vals.get(s)
        cls = "k" if v is not None else "v"
        bits.append(f"<span class=row><span class={cls}>{_esc(s)}</span>"
                    f"  <span class=v>{_esc(v) if v is not None else '—'}</span></span>")
    return "".join(bits)


def render_vantage(cfg) -> str:
    exports, warnings = _vantage_exports(cfg)
    merged = merge_exports(exports)
    sources = merged["sources"]
    divs = merged["divergences"]
    presence = [a for a in divs if a["divergence"] == "presence"]
    value = [a for a in divs if a["divergence"] == "value"]

    parts = [
        "<!doctype html><html lang=pt-br><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        "<title>Padmé — multi-vantage</title><style>", _CSS, "</style></head><body>",
        "<header><div class=top>",
        "<div class=brand>🛰️ PADMÉ<small>multi-vantage</small></div>",
        "<div class=spacer></div>",
        f"<span class=pill>fontes <b>{len(sources)}</b></span>",
        f"<span class=pill>ativos <b>{merged['asset_count']}</b></span>",
        '<a class=xbtn href="/">← superfície</a>',
        "</div></header><div class=wrap>",
    ]
    for w in warnings:
        parts.append(f"<div class=note>⚠ {_esc(w)}</div>")

    parts.append("<div class=eyebrow>fontes (pontos de observação)</div>")
    parts.append("<div class=panel><div class=calm>"
                 + (" · ".join(f"<b>{_esc(s)}</b>" for s in sources) or "nenhuma fonte")
                 + "</div></div>")

    # divergências de PRESENÇA (visto de umas fontes, ausente em outras)
    parts.append(f"<div class=eyebrow>divergência de presença · {len(presence)}</div>")
    if not presence:
        parts.append("<div class=panel><div class=calm>" + _chip("s-ok", "sem divergência")
                     + "<span>todo ativo aparece em todas as fontes.</span></div></div>")
    else:
        rows = []
        for a in presence:
            rows.append(
                "<div class=prow>"
                f"<div>{_chip('s-warn', 'presença')}</div>"
                f"<div><div class=who>{_esc(a['kind'].upper())} · {_esc(a['key'])}</div>"
                f"<div class=det>visto de {_esc(', '.join(a['sources_seen']))} · "
                f"ausente em {_esc(', '.join(a['sources_missing']))}</div></div>"
                f"<div class=tgt>{_esc(a['target'])}</div>"
                "</div>")
        parts.append("<div class=panel>" + "".join(rows) + "</div>")

    # divergência de VALOR (visto de todas, mas com valor diferente)
    parts.append(f"<div class=eyebrow>divergência de valor · {len(value)}</div>")
    if not value:
        parts.append("<div class=panel><div class=calm>" + _chip("s-ok", "sem divergência")
                     + "<span>ativos presentes em todas as fontes têm o mesmo valor.</span></div></div>")
    else:
        rows = []
        for a in value:
            rows.append(
                "<div class=kind>"
                f"<div class=who>{_chip('s-info', 'valor')} {_esc(a['kind'].upper())} · "
                f"{_esc(a['key'])} <span class=tgt>{_esc(a['target'])}</span></div>"
                + _vantage_values(a, sources) + "</div>")
        parts.append("<div class=panel>" + "".join(rows) + "</div>")

    parts.append("<footer>Padmé · multi-vantage · consolida exports por (target, kind, key) "
                 "— mesma lógica do <code>padme merge</code>, sem DB central</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


def _render(cfg, exposed: bool = False, only: str | None = None,
            authed: bool = False) -> str:
    trend_days = 30
    storage = _open_ro(cfg)
    try:
        rows = storage.all_state() if storage else []  # TODOS os alvos do banco
        db_targets = sorted({r["target"] for r in rows})
        all_targets = sorted(set(cfg.targets) | set(db_targets))
        # filtro por domínio (?target=): exato, com fallback p/ substring
        if only:
            shown = [t for t in all_targets if t == only] or [t for t in all_targets if only in t]
        else:
            shown = all_targets
        if storage:
            events = {t: storage.recent_events(t, 20) for t in shown}
            trend = {t: storage.events_per_day(t, trend_days) for t in shown}
            meta = {t: storage.target_meta(t) for t in shown}
        else:  # sem banco ainda: página vazia, nada é criado
            events, meta = {t: [] for t in shown}, {t: None for t in shown}
            trend = {t: [] for t in shown}
    finally:
        if storage:
            storage.close()

    by_target: dict[str, dict[str, list]] = {t: {} for t in shown}
    for r in rows:
        if r["target"] in by_target:
            by_target[r["target"]].setdefault(r["kind"], []).append(r)

    problems = _collect_problems(by_target, meta)
    explain = _explainability(events)

    parts = [
        "<!doctype html><html lang=pt-br><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        # auto-refresh é feito por JS (não <meta refresh>): ele PAUSA enquanto você
        # filtra/foca um campo, para não apagar a filtragem a cada 30s.
        "<title>Padmé — superfície</title><style>", _CSS, "</style></head><body>",
        "<header><div class=top>",
        "<div class=brand>🛰️ PADMÉ<small>attack surface monitor</small></div>",
        "<div class=spacer></div>",
        f"<span class=pill>alvos <b>{len(all_targets)}</b></span>",
        f"<span class=pill>atualizado <b>{datetime.now():%d/%m %H:%M:%S}</b></span>",
        "<span class=pill id=autopill data-secs=30>auto <b>30s</b></span>",
        "</div></header><div class=wrap>",
    ]
    if exposed and not authed:
        parts.append("<div class=banner>⚠️ Painel exposto fora de localhost e SEM autenticação. "
                     "Qualquer um com acesso à rede vê sua superfície de ataque — "
                     "defina <code>PADME_WEB_TOKEN</code> ou sirva atrás de um proxy autenticado.</div>")
    elif exposed and authed:
        parts.append("<div class=note>🔒 Painel exposto fora de localhost, protegido por token "
                     "(navegador: login com qualquer usuário e o token como senha; "
                     "automação: <code>Authorization: Bearer</code>).</div>")
    toolbar = "<div class=toolbar>"
    if len(all_targets) > 1:
        toolbar += _filter_form(all_targets, only)
    if cfg.web.vantage_dir:
        toolbar += '<a class=xbtn href="/vantage">multi-vantage →</a>'
    toolbar += _export_actions(only)
    parts.append(toolbar + "</div>")

    scope = f" · {only}" if only else ""
    parts.append(f"<div class=eyebrow>visão geral{scope}</div>")
    parts.append(_global_kpis(by_target, meta, problems, len(shown), explain))

    parts.append(f"<div class=eyebrow>problemas abertos · {len(problems)}</div>")
    parts.append(_problems_panel(problems))

    parts.append("<div class=eyebrow>alvos</div>")
    if not shown:
        parts.append("<div class=panel><div class=empty>nenhum alvo"
                     + (f" casa com o filtro '{_esc(only)}'." if only
                        else " ainda — rode <code>padme scan</code> ou <code>padme monitor</code>.")
                     + "</div></div>")
    for target in shown:
        parts.append(_host_card(target, by_target.get(target, {}), events.get(target, []),
                                trend.get(target, []), meta.get(target), trend_days))

    parts.append("<footer>Padmé · painel read-only · lê o padme.db, não altera nada</footer>")
    parts.append("</div>")
    parts.append(_TREND_JS)
    parts.append("</body></html>")
    return "".join(parts)


def _bearer_ok(header: str | None, token: str) -> bool:
    """Valida `Authorization: Bearer <token>` em tempo constante.

    Header ausente/malformado -> False. Comparação com `hmac.compare_digest`
    (não vaza o tamanho/prefixo do token por timing). Chamado só quando há token
    configurado."""
    if not header:
        return False
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    # compara em bytes: cabeçalhos chegam decodificados em latin-1, e
    # compare_digest levanta TypeError com str não-ASCII — encode fecha isso
    # (mantém tempo constante) e nunca deixa a exceção escapar como 500.
    return hmac.compare_digest(parts[1].strip().encode("utf-8"), token.encode("utf-8"))


def _auth_ok(header: str | None, token: str) -> bool:
    """Aceita `Bearer <token>` (curl/automação) OU `Basic` — o que o NAVEGADOR
    envia sozinho depois do prompt de login (usuário qualquer, senha = token).
    Tempo constante nos dois; qualquer coisa malformada -> False (nunca 500)."""
    if not header:
        return False
    parts = header.split(None, 1)
    if len(parts) != 2:
        return False
    scheme = parts[0].lower()
    if scheme == "bearer":
        return _bearer_ok(header, token)
    if scheme != "basic":
        return False
    try:
        raw = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
    except Exception:  # noqa: BLE001 — base64/utf-8 inválido
        return False
    _user, sep, password = raw.partition(":")
    if not sep:
        return False
    return hmac.compare_digest(password.encode("utf-8"), token.encode("utf-8"))


_ROUTES = ("/", "/export", "/vantage")  # rotas conhecidas (após auth)

# CSP compatível com o HTML real do painel: <style>/<script> e style="" inline
# (daí 'unsafe-inline'), ícones/imagens só como data:, formulário GET p/ mesma
# origem. Sem fontes/JS externos — o painel é 100% self-contained.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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


def make_handler(page_cfg, exposed: bool, auth_token: str | None):
    """Fábrica do handler HTTP (fecha sobre cfg/exposed/token). Separada de
    `serve` para ser testável sem depender de `serve_forever`."""

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
            try:
                self._route(route, urllib.parse.parse_qs(parsed.query))
            except StorageOutdated as exc:
                # o painel só LÊ: quem migra o schema é o monitor/scan/doctor
                self._write(503, "text/plain; charset=utf-8", f"503 {exc}\n".encode("utf-8"))

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
                               authed=auth_token is not None).encode("utf-8")
                self._write(200, "text/html; charset=utf-8", body)

        def log_message(self, *args):
            pass  # nunca loga requests (evita vazar o token de um header em log)

    return Handler


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
