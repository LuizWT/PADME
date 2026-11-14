"""Moldura das páginas: sidebar, filtro por domínio, ações de export e o
esqueleto HTML.
"""

from __future__ import annotations

import urllib.parse

from .assets import _CSS, _LOGO
from .html import (
    _esc,
    _icon,
    _slug,
)


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
