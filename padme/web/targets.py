"""Tabela de alvos e dossiê por alvo: risco aberto, saúde, linha do tempo e
inventário.
"""

from __future__ import annotations

from .html import (
    _ARROW,
    _KIND_LABEL,
    _KIND_ORDER,
    _SEV,
    _changes_html,
    _chip,
    _diff_line,
    _esc,
    _port_fp,
    _proof_html,
    _slug,
    _ts_human,
)
from .metrics import (
    _prioritize_events,
)
from .overview import (
    _health,
    _stat_tiles,
    _trend,
)


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


# ── timeline (dossiê) ───────────────────────────────────────────────────────
_EV_VERB = {"added": "novo", "removed": "removido", "changed": "alterado"}


_EV_LEVEL = {"s-crit": "lv-crit", "s-serious": "lv-serious", "s-warn": "lv-warn"}


_EVENTS_VISIBLE = 6


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
