"""Painel web da superfície de ataque (só stdlib, sem dependências).

Lê o padme.db e mostra, num relance: um resumo global, os problemas abertos
(takeover, cert expirando, wildcard, e-mail, coleta parcial) priorizados por
severidade, e um dossiê por alvo com saúde da coleta, tendência e eventos.

Leitura por padrão: a única escrita é a ação de finding (reconhecer,
silenciar, aceitar risco, reabrir) via POST /finding, com token de CSRF e
checagem de origem — desligável com `web.actions: false` e nunca ligada em
painel exposto sem auth. Bind em localhost por padrão.

Design: paleta escura validada (status good/warning/serious/critical com
chip = ponto + rótulo, nunca cor sozinha), tipografia de sistema, hairlines,
`tabular-nums` nos números. Renderização no servidor; o navegador só troca o
conteúdo quando o /live avisa que o banco mudou.

Módulos, de baixo para cima:

  html       peças usadas por todas as páginas (escape, chips, datas, diff)
  assets     CSS, JS e logo (strings estáticas)
  metrics    números dos cartões (sem HTML)
  problems   painel de problemas abertos e menu de ações
  overview   KPIs, tendência, atividade, saúde dos collectors
  targets    tabela de alvos e dossiê por alvo
  layout     moldura da página (sidebar, filtro, export)
  pages      páginas completas: visão geral, export e multi-vantage
  auth       Bearer, Basic e checagem de origem
  server     servidor HTTP, ações POST, /live e o modo em thread
"""

from .pages import render_export, render_vantage
from .server import PanelServer, make_handler, serve, start_background

__all__ = ["PanelServer", "make_handler", "render_export", "render_vantage", "serve",
           "start_background"]
