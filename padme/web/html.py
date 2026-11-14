"""Peças de HTML usadas por todas as páginas do painel: escape, chips, datas,
diff por campo, evidência e ícones.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from ..evidence import evidence_of
from ..models import Event
from ..risk import Level

_KIND_ORDER = ["takeover", "cert_expiry", "ns", "mailsec", "wildcard",
               "subdomain", "port", "http", "httpsec", "favicon", "tls", "dns"]


_KIND_LABEL = {
    "takeover": "TAKEOVER", "cert_expiry": "CERT", "ns": "NS", "mailsec": "E-MAIL",
    "wildcard": "WILDCARD", "subdomain": "SUBDOMAIN", "port": "PORT",
    "http": "HTTP", "httpsec": "HEADERS", "favicon": "FAVICON", "tls": "TLS", "dns": "DNS",
}


_ARROW = {"added": "+", "removed": "−", "changed": "~"}


def _esc(s: object) -> str:
    # NÃO use `s or ""`: 0 e False são válidos e viram "" assim (o tile de
    # "portas abertas" com contagem 0 ficava EM BRANCO). Só None é vazio.
    return html.escape("" if s is None else str(s))


def _ts_human(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%d/%m %H:%M")
    except Exception:
        return "—"


def _changes_html(changes: dict[str, Any] | None) -> str:
    """Detalhe do diff semântico de um CHANGED: campo: old → new."""
    if not changes:
        return ""
    def fmt(v: object) -> object:  # conjuntos (DNS, SANs do TLS) em texto, não repr de lista
        return ", ".join(map(str, v)) if isinstance(v, list) else v

    bits = [f"{_esc(f)}: {_esc(fmt(ch.get('old')))} → {_esc(fmt(ch.get('new')))}"
            for f, ch in changes.items()]
    return "<span class=chgdet>" + " · ".join(bits) + "</span>"


def _proof_html(e: Event, value: str | None) -> str:
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


def _port_fp(metadata: dict[str, Any] | None) -> str:
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


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower())


def _diff_line(cls: str, mark: str, value: object) -> str:
    return f"<div class={cls}><span class=mk>{mark}</span>{_esc(value)}</div>"


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
