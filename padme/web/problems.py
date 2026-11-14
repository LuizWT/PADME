"""Painel de problemas abertos: linhas, prazo (SLA), status e menu de ações.
"""

from __future__ import annotations

import time

from ..findings import (
    ACCEPTED,
    ACKNOWLEDGED,
    DEFAULT_SLA_HOURS,
    MUTED,
    OPEN,
    STATUS_LABEL,
    SUPPRESSED,
    human_hours,
    sla_info,
)
from .html import (
    _chip,
    _esc,
    _slug,
)

# ── problemas abertos (agregado, priorizado, com ciclo de vida) ─────────────
_PROBLEMS_VISIBLE = 8  # o resto fica num "mais N" — a lista não engole a página


_STATUS_CLS = {OPEN: "s-muted", ACKNOWLEDGED: "s-info", SUPPRESSED: "s-muted", ACCEPTED: "s-muted"}


def _sla_of(p: dict, sla_hours: dict, now: float) -> dict | None:
    row = p.get("row") or {}
    if not row:
        return None
    return sla_info({**row, "status": p.get("status", OPEN), "severity": p.get("severity", "")},
                    now, sla_hours)


def _status_cell(p: dict, sla_hours: dict, now: float) -> str:
    """Estado do finding: status + há quanto tempo + prazo (ou o motivo, se tratado)."""
    if not p.get("id"):  # COLETA: operacional e transitório, sem ciclo de vida
        return "<span class=lghint>transitório</span>"
    st = p.get("status", OPEN)
    row = p.get("row") or {}
    bits = [_chip(_STATUS_CLS.get(st, "s-muted"), STATUS_LABEL.get(st, st))]
    info = _sla_of(p, sla_hours, now)
    if st in MUTED:
        why = row.get("status_reason") or ""
        who = row.get("status_by") or ""
        if why or who:
            bits.append(f"<div class=stx>{_esc(why)}{' · ' if why and who else ''}"
                        f"{'por ' + _esc(who) if who else ''}</div>")
    elif info is None:
        bits.append("<div class=stx>novo · aguardando o próximo scan</div>")
    else:
        line = f"há {human_hours(info['age_h'])}"
        if info["limit_h"]:
            line += (f" · <span class=late>prazo estourado há {human_hours(info['left_h'])}</span>"
                     if info["breached"] else f" · vence em {human_hours(info['left_h'])}")
        bits.append(f"<div class=stx>{line}</div>")
    return "".join(bits)


def _actions(p: dict, act: dict | None) -> str:
    """Formulário de ação do finding (POST com token de CSRF). `act` None =
    painel read-only (ações desligadas ou painel exposto sem auth)."""
    if not act or not p.get("id"):
        return ""
    st = p.get("status", OPEN)
    buttons = []
    if st == OPEN:
        buttons.append(("ack", "Reconhecer"))
    if st in (OPEN, ACKNOWLEDGED):
        buttons += [("suppress", "Falso positivo"), ("accept", "Aceitar risco")]
    if st != OPEN:
        buttons.append(("reopen", "Reabrir"))
    needs_reason = any(a in ("suppress", "accept") for a, _ in buttons)
    reason = ("<input class=actr name=reason maxlength=500 autocomplete=off "
              "placeholder='motivo' aria-label='motivo'>"
              "<span class=acth>obrigatório para falso positivo e aceitar risco</span>"
              if needs_reason else "")
    btns = "".join(f"<button class=actbtn type=submit name=action value={a}>{label}</button>"
                   for a, label in buttons)
    return ("<details class=act><summary>ações</summary>"
            "<form method=post action='/finding' class=actf>"
            f"<input type=hidden name=csrf value='{_esc(act['csrf'])}'>"
            f"<input type=hidden name=id value='{_esc(p['id'])}'>"
            f"<input type=hidden name=target value='{_esc(act.get('target') or '')}'>"
            f"{reason}<div class=actb>{btns}</div></form></details>")


def _problem_row(p: dict, act: dict | None = None, sla_hours: dict | None = None,
                 now: float | None = None) -> str:
    sla_hours = DEFAULT_SLA_HOURS if sla_hours is None else sla_hours
    now = time.time() if now is None else now
    proof = p.get("evidence")
    proof_html = f"<div class=proof>prova: {_esc(proof)}</div>" if proof else ""
    fid = f"<span class=fid title='id do finding (padme finding show …)'>{_esc(p['id'][:10])}</span>" \
        if p.get("id") else ""
    return ("<tr>"
            f"<td class=nw>{_chip(p['cls'], p['sev'])}</td>"
            f"<td><div class=who><span class=kd>{_esc(p['kind'])}</span>{_esc(p['who'])}{fid}</div>"
            f"<div class=det>{_esc(p['det'])}</div>{proof_html}</td>"
            f"<td class=st>{_status_cell(p, sla_hours, now)}{_actions(p, act)}</td>"
            f"<td class=tgt><a href='#h-{_slug(p['tgt'])}'>{_esc(p['tgt'])}</a></td>"
            "</tr>")


# colunas fixas: a tabela principal, o "mais N" e os "tratados" ficam alinhados
_PROBLEMS_COLS = ("<colgroup><col class=c-sev><col><col class=c-st><col class=c-tgt>"
                  "</colgroup>")


_PROBLEMS_HEAD = (_PROBLEMS_COLS + "<thead><tr><th>severidade</th><th>problema</th>"
                  "<th>estado</th><th>alvo</th></tr></thead>")


def _problems_panel(problems: list[dict], treated: list[dict] | None = None,
                    act: dict | None = None, sla_hours: dict | None = None) -> str:
    now = time.time()
    treated = treated or []

    def rows(items):
        return "".join(_problem_row(p, act, sla_hours, now) for p in items)

    head = ("<div class=cardhd><h3>Problemas abertos</h3><span class=sub>ordenado por risco</span>"
            f"<span class=right>{len(problems)}</span></div>")
    out = ["<section class=card id=problems>", head]
    if not problems:
        out.append("<div class=calm>" + _chip("s-ok", "tudo ok")
                   + "<span>nenhum problema aberto na superfície monitorada.</span></div>")
    else:
        first, rest = problems[:_PROBLEMS_VISIBLE], problems[_PROBLEMS_VISIBLE:]
        out.append("<div class=scroll><table class='t pt'>" + _PROBLEMS_HEAD + "<tbody>"
                   + rows(first) + "</tbody></table></div>")
        if rest:
            out.append(f"<details class=more data-persist='problems-more'><summary>mais {len(rest)} "
                       "problema(s)</summary><div class=scroll><table class='t pt'>"
                       + _PROBLEMS_COLS + "<tbody>" + rows(rest) + "</tbody></table></div></details>")
    if treated:  # silenciados / risco aceito: fora da conta, mas à vista (e reabríveis)
        out.append(f"<details class=more data-persist='problems-treated'><summary>{len(treated)} "
                   "tratado(s) · falso positivo ou risco aceito</summary>"
                   "<div class=scroll><table class='t pt'>" + _PROBLEMS_COLS + "<tbody>"
                   + rows(treated) + "</tbody></table></div></details>")
    out.append("</section>")
    return "".join(out)
