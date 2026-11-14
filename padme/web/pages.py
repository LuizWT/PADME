"""Páginas completas: visão geral (`_render`), export JSON/CSV e multi-vantage.
Abre o banco só para leitura.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

from ..merge import merge_exports
from ..storage import Storage
from .assets import _TREND_JS
from .html import (
    _chip,
    _esc,
    _ts_human,
)
from .layout import (
    _export_actions,
    _filter_form,
    _page,
    _sidebar,
)
from .metrics import (
    _collect_problems,
    _explainability,
)
from .overview import (
    _activity,
    _collectors_card,
    _global_kpis,
    _kpi,
)
from .problems import (
    _problems_panel,
)
from .targets import (
    _host_card,
    _host_level,
    _targets_table,
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
            authed: bool = False, csrf: str = "") -> str:
    """Página principal. `csrf` não-vazio = ações de finding ligadas (o handler
    só passa o token quando `web.actions` está on e o painel não está exposto
    sem auth); vazio = painel estritamente read-only."""
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
            statuses = storage.finding_rows(shown) if shown else {}
        else:  # sem banco ainda: página vazia, nada é criado
            events, meta = {t: [] for t in shown}, {t: None for t in shown}
            statuses = {}
            trend = {t: [] for t in shown}
    finally:
        if storage:
            storage.close()

    by_target: dict[str, dict[str, list]] = {t: {} for t in shown}
    for r in rows:
        if r["target"] in by_target:
            by_target[r["target"]].setdefault(r["kind"], []).append(r)

    problems = _collect_problems(by_target, meta, statuses)
    treated = _collect_problems(by_target, meta, statuses, include_muted=True)
    explain = _explainability(events)
    sla_hours = cfg.findings.sla_hours
    act = {"csrf": csrf, "target": only or ""} if csrf else None
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

    body.append(_global_kpis(by_target, meta, problems, len(shown), explain, sla_hours))
    body.append("<div class=grid2>" + _problems_panel(problems, treated, act, sla_hours)
                + "<div class=stack>" + _activity(trend, trend_days) + _collectors_card(meta)
                + "</div></div>")

    body.append(f"<div class=sectitle><h2>Alvos</h2><span>{len(shown)} no escopo</span></div>")
    if not shown:
        body.append("<section class=card id=targets><div class=empty>nenhum alvo"
                    + (f" casa com o filtro '{_esc(only)}'." if only
                       else " ainda — rode <code>padme</code> ou <code>padme scan</code>.")
                    + "</div></section>")
    else:
        body.append(_targets_table(shown, by_target, meta, trend, problems))
        body.append("<div class=sectitle><h2>Dossiês</h2>"
                    "<span>resumo, timeline priorizada e inventário por alvo</span></div>")
        for target in shown:
            body.append(_host_card(target, by_target.get(target, {}), events.get(target, []),
                                   trend.get(target, []), meta.get(target), trend_days, problems))
    body.append("<footer>Padmé · " + ("lê o padme.db; só grava ações de finding (com CSRF)"
                if csrf else "painel read-only · lê o padme.db, não altera nada") + "</footer>")

    hot = any(p["cls"] in ("s-crit", "s-serious") for p in problems)
    # ao vivo: /live avisa quando o banco muda e o JS troca o conteúdo da página
    # (sem recarregar); o indicador mostra se está ao vivo, em espera ou sem conexão
    foot = (f"<div class=row2><span>último ciclo</span><b>{_esc(last_cycle)}</b></div>"
            f"<div class=row2><span>atualizado</span><b>{datetime.now():%H:%M:%S}</b></div>"
            "<div class=row2><span>painel</span>"
            "<span class='pill live-on' id=autopill data-live=1><span class=ldot></span>"
            "ao vivo</span></div>")
    side = _sidebar("overview", n_problems=len(problems), n_targets=len(shown), hot=hot,
                    vantage=bool(cfg.web.vantage_dir),
                    targets_nav=[(t, _host_level(by_target.get(t, {}), meta.get(t))[0])
                                 for t in shown],
                    foot=foot)
    return _page("Padmé — superfície", side, "".join(body), _TREND_JS)
