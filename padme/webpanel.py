"""Painel web read-only da superfície de ataque — visão de monitoração (ZABBIX-like).

Serve uma página HTML (só stdlib, sem dependências) que lê o padme.db e mostra,
num relance: um resumo global, um painel de PROBLEMAS abertos (takeover, cert
expirando, wildcard, coleta parcial) priorizado por severidade, e um cartão por
alvo com saúde da coleta, KPIs da superfície, tendência e últimos eventos.

Só leitura — não altera nada. Bind em localhost por padrão.

Design: paleta escura validada (status good/warning/serious/critical com
chip = ponto + rótulo, nunca cor sozinha), tipografia de sistema, hairlines,
`tabular-nums` nos números. Layout de console: sidebar de navegação, visão
geral (KPIs, problemas, atividade, saúde dos collectors), tabela de alvos e um
dossiê por alvo. Renderização server-side; auto-refresh por JS (pausável).
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
from .panel_assets import _CSS, _LOGO, _TREND_ADD, _TREND_CHG, _TREND_JS, _TREND_REM
from .panel_metrics import (
    _collect_problems,
    _collector_reliability,
    _collector_table,
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
    return f"<span class=tag title='{_esc(full)}'>prova: {_esc(typ)}</span>"


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
_PROBLEMS_VISIBLE = 8  # o resto fica num "mais N" — a lista não engole a página


def _problem_row(p: dict) -> str:
    proof = p.get("evidence")
    proof_html = f"<div class=proof>prova: {_esc(proof)}</div>" if proof else ""
    return ("<tr>"
            f"<td class=nw>{_chip(p['cls'], p['sev'])}</td>"
            f"<td><div class=who><span class=kd>{_esc(p['kind'])}</span>{_esc(p['who'])}</div>"
            f"<div class=det>{_esc(p['det'])}</div>{proof_html}</td>"
            f"<td class=tgt><a href='#h-{_slug(p['tgt'])}'>{_esc(p['tgt'])}</a></td>"
            "</tr>")


def _problems_panel(problems: list[dict]) -> str:
    head = ("<div class=cardhd><h3>Problemas abertos</h3><span class=sub>ordenado por risco</span>"
            f"<span class=right>{len(problems)}</span></div>")
    if not problems:
        return ("<section class=card id=problems>" + head + "<div class=calm>"
                + _chip("s-ok", "tudo ok")
                + "<span>nenhum problema aberto na superfície monitorada.</span></div></section>")
    first, rest = problems[:_PROBLEMS_VISIBLE], problems[_PROBLEMS_VISIBLE:]
    out = ["<section class=card id=problems>", head,
           "<div class=scroll><table class=t><thead><tr><th>severidade</th><th>problema</th>"
           "<th>alvo</th></tr></thead><tbody>", *map(_problem_row, first), "</tbody></table></div>"]
    if rest:
        out += [f"<details class=more data-persist='problems-more'><summary>mais {len(rest)} "
                "problema(s)</summary><div class=scroll><table class=t><tbody>",
                *map(_problem_row, rest), "</tbody></table></div></details>"]
    out.append("</section>")
    return "".join(out)


# ── KPIs globais ────────────────────────────────────────────────────────────
def _kpi(n, label: str, sub: str = "", cls: str = "") -> str:
    sub_html = f"<div class=s>{_esc(sub)}</div>" if sub else ""
    return (f"<div class='kpi {cls}'><div class=l>{_esc(label)}</div>"
            f"<div class=n>{_esc(n)}</div>{sub_html}</div>")


def _global_kpis(by_target: dict, meta: dict, problems: list[dict], n_targets: int,
                 explain: dict | None = None) -> str:
    assets = sum(len(v) for kinds in by_target.values() for v in kinds.values())
    crit = sum(1 for p in problems if p["cls"] in ("s-crit", "s-serious"))
    prob_cls = "crit" if crit else ("warn" if problems else "ok")
    tiles = [
        _kpi(n_targets, "alvos monitorados", f"{len(by_target)} com dados", cls="accent"),
        _kpi(assets, "ativos observados", "subdomínios, portas, serviços…"),
        _kpi(len(problems), "problemas abertos",
             f"{crit} de alta gravidade" if problems else "superfície limpa", cls=prob_cls),
    ]
    rel = _collector_reliability(meta)
    if rel:  # §27: confiabilidade dos collectors (só quando há saúde registrada)
        cls = "crit" if rel["has_error"] else ("warn" if rel["degraded"] else "ok")
        sub = (f"{rel['ok']}/{rel['total']} observações ok"
               if not rel["degraded"] else
               f"{rel['ok']}/{rel['total']} ok · degradado: " + ", ".join(rel["degraded"]))
        tiles.append(_kpi(f"{rel['pct']}%", "collectors confiáveis", sub, cls=cls))
    else:  # sem saúde por collector gravada: cai p/ a visão por alvo (parcial ou não)
        partial = sum(1 for m in meta.values() if m and m.get("last_partial"))
        ok_hosts = sum(1 for t in by_target if not (meta.get(t) or {}).get("last_partial"))
        tiles.append(_kpi(f"{ok_hosts}/{len(by_target) or 0}", "coleta saudável",
                          f"{partial} parcial(is)" if partial else "sem coleta parcial",
                          cls=("warn" if partial else "ok")))
    if explain:  # §27: só aparece quando há evento HIGH/CRITICAL recente p/ medir
        pct = explain["pct"]
        cls = "ok" if pct == 100 else ("warn" if pct >= 50 else "crit")
        sub = (f"{explain['explained']}/{explain['high']} HIGH+ com razão, proveniência e evidência"
               if pct == 100 else
               f"{explain['explained']}/{explain['high']} HIGH+ · falta "
               + ", ".join(explain["missing"]))
        tiles.append(_kpi(f"{pct}%", "alertas explicáveis", sub, cls=cls))
    return "<section id=overview class=kpis>" + "".join(tiles) + "</section>"


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
                 'stroke="#2a3240" stroke-width="1"/>')
    if max_total > 0:
        parts.append(f'<text x="{pad_l - 4:.1f}" y="{pad_t + 4:.1f}" text-anchor="end" '
                     f'font-size="9" fill="#7c8696">{max_total}</text>')
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
                         f'font-size="9" fill="#7c8696">{label}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _trend(serie: list[dict], days: int, title: str = "tendência") -> str:
    total = sum(d["total"] for d in serie)
    added = sum(d["added"] for d in serie)
    removed = sum(d["removed"] for d in serie)
    net = added - removed
    net_s = f"+{net}" if net > 0 else str(net)
    out = [f'<div class=trend data-days="{days}"><div class=hd>'
           f'<b>{_esc(title)} · {days}d</b><span class=lghint>sem registros DNS</span>']
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


def _activity(trend: dict, days: int) -> str:
    """Atividade de TODOS os alvos exibidos: soma as séries diárias por dia."""
    agg: dict[str, dict] = {}
    for serie in trend.values():
        for d in serie:
            a = agg.setdefault(d["day"], {"day": d["day"], "added": 0, "removed": 0,
                                          "changed": 0, "total": 0})
            for k in ("added", "removed", "changed", "total"):
                a[k] += d[k]
    serie = [agg[k] for k in sorted(agg)]
    return "<section class=card>" + _trend(serie, days, title="atividade") + "</section>"


_HEALTH_CLS = {"ok": "s-ok", "partial": "s-warn", "error": "s-crit"}


def _collectors_card(meta: dict) -> str:
    """Tabela de saúde por collector (consolidada entre alvos). Some quando não
    há saúde gravada — sem card vazio."""
    rows = _collector_table(meta)
    if not rows:
        return ""
    trs = []
    for r in rows:
        pct = round(100 * r["ok"] / r["total"]) if r["total"] else 0
        bar = {"error": "crit", "partial": "warn"}.get(r["worst"], "")
        trs.append(
            f"<tr><td class=mono>{_esc(r['name'])}</td>"
            f"<td><div class='bar {bar}'><i style='width:{pct}%'></i></div></td>"
            f"<td class=r>{r['ok']}/{r['total']}</td>"
            f"<td class=r>{_chip(_HEALTH_CLS[r['worst']], r['worst'])}</td></tr>")
    return ("<section class=card><div class=cardhd><h3>Saúde dos collectors</h3>"
            "<span class=sub>último scan, por alvo</span></div>"
            "<div class=scroll><table class=t><thead><tr><th>collector</th><th></th><th class=r>ok</th>"
            "<th class=r>pior</th></tr></thead><tbody>" + "".join(trs)
            + "</tbody></table></div></section>")


# ── saúde da coleta por alvo ────────────────────────────────────────────────
def _health(meta: dict | None) -> str:
    if not meta:
        return "<div class=health><span class=lghint>sem scan registrado ainda.</span></div>"
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
    kv = [("último scan", _ts_human(meta.get("last_scan_at"))),
          ("último scan ok", _ts_human(meta.get("last_success_at")))]
    if errs is not None:
        kv.append(("erros", errs))
    if dur is not None:
        kv.append(("duração", f"{dur} ms"))
    out = (f"<div class=health>{chip}</div><dl class=kv>"
           + "".join(f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>" for k, v in kv) + "</dl>")
    # saúde POR collector (DNS ok / PORTS partial / CT error) — §7 do roadmap
    ch = meta.get("collectors_health") or {}
    if ch:
        chips = "".join(
            f"<span class=chp>{_esc(name)} "
            f"{_chip(_HEALTH_CLS.get(v.get('status'), 's-muted'), v.get('status', '?'))}</span>"
            for name, v in sorted(ch.items()))
        out += f"<div class=collhealth>{chips}</div>"
    return out


def _host_level(kinds: dict, meta: dict | None) -> tuple[str, str]:
    """(classe de status, rótulo) do alvo — o mesmo no dossiê, na tabela e na sidebar."""
    if kinds.get("takeover"):
        return "s-crit", "takeover"
    if kinds.get("cert_expiry"):
        return "s-serious", "cert"
    if (meta or {}).get("last_partial") or kinds.get("wildcard"):
        return "s-warn", "atenção"
    if not kinds:
        return "s-muted", "sem dados"
    return "s-ok", "ok"


def _host_status(kinds: dict, meta: dict | None) -> str:
    return _chip(*_host_level(kinds, meta))


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower())


# ── timeline (dossiê) ───────────────────────────────────────────────────────
_EV_VERB = {"added": "novo", "removed": "removido", "changed": "alterado"}
_EV_LEVEL = {"s-crit": "lv-crit", "s-serious": "lv-serious", "s-warn": "lv-warn"}
_EVENTS_VISIBLE = 6


def _diff_line(cls: str, mark: str, value) -> str:
    return f"<div class={cls}><span class=mk>{mark}</span>{_esc(value)}</div>"


def _event_html(e, risk) -> str:
    t = e.event_type.value
    val = e.new_value if t != "removed" else e.old_value
    when = (e.detected_at or "")[5:16].replace("T", " ")
    scls, slabel = _SEV.get(risk.level, ("s-muted", ""))
    md = e.metadata or {}
    diff = []
    if t == "changed":
        if e.old_value:
            diff.append(_diff_line("dr", "−", e.old_value))
        if e.new_value:
            diff.append(_diff_line("da", "+", e.new_value))
    elif val:
        diff.append(_diff_line("dr" if t == "removed" else "da", _ARROW[t], val))
    changes = _changes_html(md.get("_changes"))
    diff_html = f"<div class=diff>{''.join(diff)}{changes}</div>" if (diff or changes) else ""
    tags = []
    labels = risk.reason_labels()
    if risk.level > risk.base and labels:   # só destaca quando o contexto elevou
        extra = f" +{len(labels) - 1}" if len(labels) > 1 else ""
        tags.append(f"<span class='tag why' title='{_esc(' · '.join(labels))}'>▲ "
                    f"{_esc(labels[0])}{extra}</span>")
    prov = md.get("_collector") or md.get("_source")
    if prov:
        tags.append(f"<span class='tag prov' title='collector'>{_esc(prov)}</span>")
    tags.append(_proof_html(e, val))
    if risk.confidence.name != "CONFIRMED":
        tags.append(f"<span class=tag>confiança: {risk.confidence.name.lower()}</span>")
    tags_html = "".join(t_ for t_ in tags if t_)
    meta_html = f"<div class=evmeta>{tags_html}</div>" if tags_html else ""
    return (f"<div class='ev {_EV_LEVEL.get(scls, '')}'><div class=evhd>{_chip(scls, slabel)}"
            f"<span class=evkind>{_esc(e.kind.value)} · {_EV_VERB[t]}</span>"
            f"<span class=evkey>{_esc(e.key)}</span><span class=when>{_esc(when)}</span></div>"
            f"{diff_html}{meta_html}</div>")


def _timeline(target: str, events: list) -> str:
    out = ["<div class=panehd><h4>Timeline priorizada</h4>"
           f"<span>{len(events)} evento(s) recentes · mais relevante primeiro</span></div>"]
    if not events:
        out.append("<div class=empty>sem eventos recentes.</div>")
        return "".join(out)
    ranked = [_event_html(e, r) for e, r in _prioritize_events(events)]
    first, rest = ranked[:_EVENTS_VISIBLE], ranked[_EVENTS_VISIBLE:]
    out += first
    if rest:
        out.append(f"<details class=more data-persist='ev-{_slug(target)}'>"
                   f"<summary>mais {len(rest)} evento(s)</summary>{''.join(rest)}</details>")
    return "".join(out)


def _risk_block(probs: list[dict]) -> str:
    if not probs:
        return "<div class=risk>" + _chip("s-ok", "nenhum") + "</div>"
    items = [f"<div class=ri><span class='dot {p['cls']}'></span><div>"
             f"<div class=w>{_esc(p['kind'])} · {_esc(p['who'])}</div>"
             f"<div class=d>{_esc(p['det'])}</div></div></div>" for p in probs[:5]]
    if len(probs) > 5:
        items.append(f"<div class=lghint>+{len(probs) - 5} na lista de problemas</div>")
    return "<div class=risk>" + "".join(items) + "</div>"


def _assets(target: str, kinds: dict, total: int) -> str:
    # detalhe completo por categoria. `data-persist`: a JS lembra aberto/
    # fechado entre os auto-refreshes de 30s (senão recolhia sozinho).
    det = [f"<details class=kinds data-persist='k-{_slug(target)}'>"
           f"<summary>Ativos por categoria <span>{total}</span></summary>",
           "<input class=kfilter type=search autocomplete=off "
           "placeholder='filtrar (host, porta, kind, valor)…' "
           "aria-label='filtrar ativos'>"]
    for kind in _KIND_ORDER:
        items = kinds.get(kind)
        if not items:
            continue
        # data-kind p/ a busca casar também o nome da categoria (ex.: 'port')
        det.append(f"<div class=kind data-kind='{kind}'><b>{_KIND_LABEL[kind]} · {len(items)}</b>")
        for it in sorted(items, key=lambda x: x["key"]):
            v = f"<span class=v>{_esc(it['value'])}</span>" if it["value"] else ""
            fp = _port_fp(it.get("metadata")) if kind == "port" else ""
            det.append(f"<div class=row><span class=k>{_esc(it['key'])}</span>{v}{fp}</div>")
        det.append("</div>")
    det.append("</details>")
    return "".join(det)


def _host_card(target: str, kinds: dict, events: list, serie: list[dict],
               meta: dict | None, trend_days: int, problems: list[dict] | None = None) -> str:
    """Dossiê do alvo: à esquerda o resumo (risco, saúde, cobertura); à direita
    a timeline priorizada com diff, a tendência e o inventário filtrável."""
    total = sum(len(v) for v in kinds.values())
    probs = [p for p in (problems or []) if p["tgt"] == target]
    last = _ts_human(meta.get("last_scan_at")) if meta else "—"
    side = ["<aside class=dosside>",
            f"<div class=blk><h4>risco aberto<span class=c>{len(probs)}</span></h4>"
            f"{_risk_block(probs)}</div>",
            f"<div class=blk><h4>saúde da coleta</h4>{_health(meta)}</div>"]
    if kinds:
        side.append(f"<div class=blk><h4>cobertura</h4>{_stat_tiles(kinds)}</div>")
    side.append("</aside>")
    main = ["<div class=dosmain>", _timeline(target, events), _trend(serie, trend_days)]
    if kinds:
        main.append(_assets(target, kinds, total))
    else:
        main.append("<div class=empty>sem baseline ainda — rode um scan para este alvo.</div>")
    main.append("</div>")
    return (f"<section class=dossier id='h-{_slug(target)}'>"
            f"<div class=doshd>{_host_status(kinds, meta)}<span class=name>{_esc(target)}</span>"
            f"<span class=meta>{total} ativo(s) · último scan {_esc(last)}</span></div>"
            f"<div class=dosbody>{''.join(side)}{''.join(main)}</div></section>")


def _targets_table(shown: list[str], by_target: dict, meta: dict, trend: dict,
                   problems: list[dict]) -> str:
    rows = []
    for t in shown:
        kinds = by_target.get(t, {})
        m = meta.get(t)
        n_prob = sum(1 for p in problems if p["tgt"] == t)
        n_ev = sum(d["total"] for d in trend.get(t, []))
        rows.append(
            f"<tr><td><a class=mono href='#h-{_slug(t)}'>{_esc(t)}</a></td>"
            f"<td>{_host_status(kinds, m)}</td>"
            f"<td class=r>{sum(len(v) for v in kinds.values())}</td>"
            f"<td class=r>{n_prob}</td><td class=r>{n_ev}</td>"
            f"<td class=r>{_esc(_ts_human(m.get('last_scan_at')) if m else '—')}</td></tr>")
    return ("<section class=card id=targets><div class=scroll><table class=t><thead><tr>"
            "<th>alvo</th><th>estado</th><th class=r>ativos</th><th class=r>problemas</th>"
            "<th class=r>eventos 30d</th><th class=r>último scan</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div></section>")


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
        '<span class=exports>'
        f'<a class=xbtn href="/export?fmt=json{q}">exportar JSON</a>'
        f'<a class=xbtn href="/export?fmt=csv{q}">CSV</a></span>'
    )


# ── shell: sidebar + página ─────────────────────────────────────────────────
# ícones de linha inline (sem fonte/arquivo externo: a CSP não deixa e nem precisa)
_ICON = {
    "overview": "<path d='M3 3h7v7H3zM14 3h7v4h-7zM14 11h7v10h-7zM3 14h7v7H3z'/>",
    "problems": "<path d='M12 3 2 21h20L12 3z'/><path d='M12 10v5M12 18v.01'/>",
    "targets": "<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='4'/>",
    "vantage": "<path d='M12 3 2 8l10 5 10-5-10-5z'/><path d='M2 16l10 5 10-5'/>",
}


def _icon(name: str) -> str:
    return ("<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.8' "
            f"stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{_ICON[name]}</svg>")


def _sidebar(active: str, *, base: str = "", n_problems: int | None = None,
             n_targets: int | None = None, hot: bool = False, vantage: bool = False,
             targets_nav: list[tuple[str, str]] | None = None, foot: str = "") -> str:
    def link(key, href, label, cnt=None, hot_=False):
        on = " class=on" if key == active else ""
        c = (f"<span class='cnt{' hot' if hot_ else ''}'>{cnt}</span>" if cnt is not None else "")
        return f"<a href='{href}'{on}>{_icon(key)}<span>{label}</span>{c}</a>"

    nav = [link("overview", f"{base}#overview", "Visão geral"),
           link("problems", f"{base}#problems", "Problemas", n_problems, hot),
           link("targets", f"{base}#targets", "Alvos", n_targets)]
    if vantage:
        nav.append(link("vantage", "/vantage", "Multi-vantage"))
    out = ["<aside class=side>",
           "<div class=logo>"
           + (f"<img class=mark src='{_LOGO}' alt=''>" if _LOGO else "<span class=mark>P</span>")
           + "<div><b>PADMÉ</b><small>attack surface monitoring</small></div></div>",
           "<div><div class=navlabel>monitoração</div><nav class=nav>" + "".join(nav) + "</nav></div>"]
    if targets_nav:
        items = "".join(
            f"<a href='#h-{_slug(t)}'><span class='dot {cls}'></span><span class=n>{_esc(t)}</span></a>"
            for t, cls in targets_nav[:15])
        more = (f"<div class=lghint style='padding:4px 10px'>+{len(targets_nav) - 15} alvo(s)</div>"
                if len(targets_nav) > 15 else "")
        out.append(f"<div class=tlistwrap><div class=navlabel>dossiês</div>"
                   f"<nav class='nav tlist'>{items}</nav>{more}</div>")
    if foot:
        out.append(f"<div class=sidefoot>{foot}</div>")
    out.append("</aside>")
    return "".join(out)


def _page(title: str, side: str, body: str, script: str = "") -> str:
    return "".join([
        "<!doctype html><html lang=pt-br><head><meta charset=utf-8>",
        "<meta name=viewport content='width=device-width,initial-scale=1'>",
        f"<title>{_esc(title)}</title>",
        f"<link rel=icon href='{_LOGO}'>" if _LOGO else "",
        "<style>", _CSS, "</style></head><body>",
        "<div class=app>", side, "<main class=main>", body, "</main></div>",
        script, "</body></html>",
    ])


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


def render_vantage(cfg) -> str:
    exports, warnings = _vantage_exports(cfg)
    merged = merge_exports(exports)
    sources = merged["sources"]
    divs = merged["divergences"]
    presence = [a for a in divs if a["divergence"] == "presence"]
    value = [a for a in divs if a["divergence"] == "value"]

    body = ["<header class=pagehead><div><h1>Multi-vantage</h1>"
            "<p>consolida exports por (target, kind, key) — mesma lógica do "
            "<code>padme merge</code>, sem DB central</p></div>"
            "<div class=actions><a class=xbtn href='/'>← voltar à superfície</a></div></header>"]
    for w in warnings:
        body.append(f"<div class=note>{_esc(w)}</div>")
    body.append("<section class=kpis>"
                + _kpi(len(sources), "fontes", " · ".join(sources) or "nenhuma fonte", cls="accent")
                + _kpi(merged["asset_count"], "ativos consolidados")
                + _kpi(len(presence), "divergência de presença", "visto de umas fontes, não de outras",
                       cls="warn" if presence else "ok")
                + _kpi(len(value), "divergência de valor", "mesmo ativo, valor diferente",
                       cls="warn" if value else "ok")
                + "</section>")

    # divergências de PRESENÇA (visto de umas fontes, ausente em outras)
    body.append("<div class=sectitle><h2>Presença</h2><span>ativo ausente em parte das fontes</span></div>")
    if not presence:
        body.append("<section class=card><div class=calm>" + _chip("s-ok", "sem divergência")
                    + "<span>todo ativo aparece em todas as fontes.</span></div></section>")
    else:
        rows = "".join(
            f"<tr><td class=nw>{_chip('s-warn', 'presença')}</td>"
            f"<td><div class=who><span class=kd>{_esc(a['kind'].upper())}</span>{_esc(a['key'])}</div>"
            f"<div class=det>visto de {_esc(', '.join(a['sources_seen']))} · "
            f"ausente em {_esc(', '.join(a['sources_missing']))}</div></td>"
            f"<td class=tgt>{_esc(a['target'])}</td></tr>" for a in presence)
        body.append("<section class=card><div class=scroll><table class=t><thead><tr><th>tipo</th>"
                    "<th>ativo</th><th>alvo</th></tr></thead><tbody>" + rows
                    + "</tbody></table></div></section>")

    # divergência de VALOR (visto de todas, mas com valor diferente)
    body.append("<div class=sectitle><h2>Valor</h2><span>valor observado por fonte (— = ausente)</span></div>")
    if not value:
        body.append("<section class=card><div class=calm>" + _chip("s-ok", "sem divergência")
                    + "<span>ativos presentes em todas as fontes têm o mesmo valor.</span></div></section>")
    else:
        head = "".join(f"<th>{_esc(s)}</th>" for s in sources)
        rows = []
        for a in value:
            vals = a.get("values", {})
            cells = "".join(f"<td class=mono>{_esc(vals[s]) if vals.get(s) is not None else '—'}</td>"
                            for s in sources)
            rows.append(f"<tr><td><div class=who><span class=kd>{_esc(a['kind'].upper())}</span>"
                        f"{_esc(a['key'])}</div><div class=tgt>{_esc(a['target'])}</div></td>{cells}</tr>")
        body.append("<section class=card><div class=scroll><table class=t><thead><tr><th>ativo</th>"
                    + head + "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>")

    body.append("<footer>Padmé · multi-vantage · painel read-only</footer>")
    side = _sidebar("vantage", base="/", vantage=True,
                    foot=f"<div class=row2><span>fontes</span><b>{len(sources)}</b></div>"
                         f"<div class=row2><span>ativos</span><b>{merged['asset_count']}</b></div>")
    return _page("Padmé — multi-vantage", side, "".join(body))


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
    scans = [m.get("last_scan_at") for m in meta.values() if m and m.get("last_scan_at")]
    last_cycle = _ts_human(max(scans)) if scans else "—"

    body = []
    scope = f" · filtro: {only}" if only else ""
    actions = (_filter_form(all_targets, only) if len(all_targets) > 1 else "") + _export_actions(only)
    body.append("<header class=pagehead><div><h1>Centro de operações</h1>"
                f"<p>visão geral{_esc(scope)} · {len(shown)} alvo(s) · somente leitura</p></div>"
                f"<div class=actions>{actions}</div></header>")
    if exposed and not authed:
        body.append("<div class=banner><b>Exposto SEM autenticação.</b><span>O painel está fora de "
                    "localhost e qualquer um com acesso à rede vê sua superfície de ataque — "
                    "defina <code>PADME_WEB_TOKEN</code> ou sirva atrás de um proxy autenticado."
                    "</span></div>")
    elif exposed and authed:
        body.append("<div class=note><b>Protegido por token.</b><span>Navegador: login com qualquer "
                    "usuário e o token como senha; automação: <code>Authorization: Bearer</code>."
                    "</span></div>")

    body.append(_global_kpis(by_target, meta, problems, len(shown), explain))
    body.append("<div class=grid2>" + _problems_panel(problems)
                + "<div class=stack>" + _activity(trend, trend_days) + _collectors_card(meta)
                + "</div></div>")

    body.append(f"<div class=sectitle><h2>Alvos</h2><span>{len(shown)} no escopo</span></div>")
    if not shown:
        body.append("<section class=card id=targets><div class=empty>nenhum alvo"
                    + (f" casa com o filtro '{_esc(only)}'." if only
                       else " ainda — rode <code>padme scan</code> ou <code>padme monitor</code>.")
                    + "</div></section>")
    else:
        body.append(_targets_table(shown, by_target, meta, trend, problems))
        body.append("<div class=sectitle><h2>Dossiês</h2>"
                    "<span>resumo, timeline priorizada e inventário por alvo</span></div>")
        for target in shown:
            body.append(_host_card(target, by_target.get(target, {}), events.get(target, []),
                                   trend.get(target, []), meta.get(target), trend_days, problems))
    body.append("<footer>Padmé · painel read-only · lê o padme.db, não altera nada</footer>")

    hot = any(p["cls"] in ("s-crit", "s-serious") for p in problems)
    # auto-refresh é feito por JS (não <meta refresh>): ele PAUSA enquanto você
    # filtra/foca um campo, para não apagar a filtragem a cada 30s.
    foot = (f"<div class=row2><span>último ciclo</span><b>{_esc(last_cycle)}</b></div>"
            f"<div class=row2><span>atualizado</span><b>{datetime.now():%H:%M:%S}</b></div>"
            "<div class=row2><span>refresh</span>"
            "<span class=pill id=autopill data-secs=30>auto <b>30s</b></span></div>")
    side = _sidebar("overview", n_problems=len(problems), n_targets=len(shown), hot=hot,
                    vantage=bool(cfg.web.vantage_dir),
                    targets_nav=[(t, _host_level(by_target.get(t, {}), meta.get(t))[0])
                                 for t in shown],
                    foot=foot)
    return _page("Padmé — superfície", side, "".join(body), _TREND_JS)


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
