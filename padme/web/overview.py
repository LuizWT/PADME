"""Visão geral do painel: KPIs, cartões da superfície, tendência, atividade e
saúde dos collectors.
"""

from __future__ import annotations

import json
import time

from ..findings import (
    DEFAULT_SLA_HOURS,
)
from .assets import _TREND_ADD, _TREND_CHG, _TREND_REM
from .html import (
    _chip,
    _esc,
    _ts_human,
)
from .metrics import (
    _collector_reliability,
    _collector_table,
)
from .problems import (
    _sla_of,
)


# ── KPIs globais ────────────────────────────────────────────────────────────
def _kpi(n, label: str, sub: str = "", cls: str = "") -> str:
    sub_html = f"<div class=s>{_esc(sub)}</div>" if sub else ""
    return (f"<div class='kpi {cls}'><div class=l>{_esc(label)}</div>"
            f"<div class=n>{_esc(n)}</div>{sub_html}</div>")


def _global_kpis(by_target: dict, meta: dict, problems: list[dict], n_targets: int,
                 explain: dict | None = None, sla_hours: dict | None = None) -> str:
    assets = sum(len(v) for kinds in by_target.values() for v in kinds.values())
    crit = sum(1 for p in problems if p["cls"] in ("s-crit", "s-serious"))
    now = time.time()
    late = sum(1 for p in problems
               if (i := _sla_of(p, DEFAULT_SLA_HOURS if sla_hours is None else sla_hours, now))
               and i["breached"])
    prob_cls = "crit" if crit or late else ("warn" if problems else "ok")
    sub = f"{crit} de alta gravidade" if problems else "superfície limpa"
    if late:
        sub += f" · {late} com prazo estourado"
    tiles = [
        _kpi(n_targets, "alvos monitorados", f"{len(by_target)} com dados", cls="accent"),
        _kpi(assets, "ativos observados", "subdomínios, portas, serviços…"),
        _kpi(len(problems), "problemas abertos", sub, cls=prob_cls),
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
