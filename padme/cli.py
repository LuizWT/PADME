"""CLI do Padmé.

Comandos:
  padme scan     -> roda um scan único e imprime as mudanças (grava baseline)
  padme monitor  -> loop contínuo; alerta no Telegram a cada mudança
  padme events   -> mostra os últimos eventos gravados de um alvo
  padme test-telegram -> envia uma mensagem de teste

Uso responsável: monitore apenas ativos que você é dono ou tem autorização
explícita para testar.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from . import __version__

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from .config import Config
from .engine import Engine, build_notifiers
from .levels import Level, filter_events, parse_level
from .models import Event
from .notify import TelegramNotifier, format_events
from .scheduler import run_monitor
from .storage import Storage

_LEVEL_CHOICES = [lv.name.lower() for lv in Level]

log = logging.getLogger("padme")


def _print_events(target: str, events: list[Event], baseline: bool) -> None:
    if baseline:
        print(f"[{target}] baseline gravado: {len(events)} itens iniciais.")
        return
    if not events:
        print(f"[{target}] sem mudanças.")
        return
    print(f"[{target}] {len(events)} mudança(s):")
    for e in events:
        arrow = {"added": "+", "removed": "-", "changed": "~"}[e.event_type.value]
        val = e.new_value if e.event_type.value != "removed" else e.old_value
        print(f"  {arrow} [{e.kind.value}] {e.key}  {val or ''}".rstrip())


async def _cmd_scan(cfg: Config, args) -> int:
    if args.level:
        cfg.telegram.level = args.level
    level = parse_level(cfg.telegram.level)
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifiers = build_notifiers(cfg) if args.notify else []
    try:
        for target in cfg.targets:
            first = not storage.is_known_target(target)
            result = await engine.scan_target(target)
            events = engine.apply(result)
            _print_events(target, events, baseline=first)
            for err in result.errors:
                log.debug("erro: %s", err)
            if notifiers and not first:
                enviar = filter_events(events, level)
                if enviar:
                    for n in notifiers:
                        await n.notify_events(target, enviar)
                elif events:
                    log.info("[%s] %d mudança(s) abaixo do nível '%s' — não notificado.",
                             target, len(events), level.name.lower())
    finally:
        storage.close()
    return 0


async def _cmd_monitor(cfg: Config, args) -> int:
    if args.interval:
        cfg.interval_seconds = args.interval
    if args.level:
        cfg.telegram.level = args.level
    await run_monitor(cfg)
    return 0


async def _cmd_events(cfg: Config, args) -> int:
    storage = Storage(cfg.db_path)
    try:
        for target in cfg.targets:
            events = storage.recent_events(target, limit=args.limit)
            print(f"=== {target} — últimos {len(events)} eventos ===")
            for e in reversed(events):
                arrow = {"added": "+", "removed": "-", "changed": "~"}[e.event_type.value]
                val = e.new_value if e.event_type.value != "removed" else e.old_value
                print(f"  {arrow} [{e.kind.value}] {e.key}  {val or ''}".rstrip())
    finally:
        storage.close()
    return 0


async def _cmd_test_telegram(cfg: Config, args) -> int:
    tg = cfg.telegram
    notifier = TelegramNotifier(tg.bot_token, tg.chat_id)
    if not notifier.configured:
        print("Telegram não configurado (bot_token/chat_id ausentes).")
        return 1
    ok = await notifier.send("🛰️ <b>Padmé</b> online. Teste de conexão OK.")
    print("Mensagem enviada." if ok else "Falha ao enviar — confira token/chat_id.")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="padme",
        description="Padmé — Attack Surface Monitoring com alerta no Telegram.",
    )
    p.add_argument("--version", action="version", version=f"padme {__version__}")
    p.add_argument("-c", "--config", default="config.yaml", help="caminho do config YAML")
    p.add_argument("-v", "--verbose", action="store_true", help="log detalhado")

    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="scan único (grava/atualiza baseline)")
    sp.add_argument("--notify", action="store_true", help="também notifica no Telegram")
    sp.add_argument("--level", choices=_LEVEL_CHOICES, default=None,
                    help="limiar de severidade enviado ao Telegram (sobrescreve o config)")
    sp.set_defaults(func=_cmd_scan)

    mp = sub.add_parser("monitor", help="modo sentinela: varre em loop e alerta no Telegram")
    mp.add_argument("--interval", type=int, default=None, help="sobrescreve interval_seconds")
    mp.add_argument("--level", choices=_LEVEL_CHOICES, default=None,
                    help="limiar de severidade enviado ao Telegram (sobrescreve o config)")
    mp.set_defaults(func=_cmd_monitor)

    ep = sub.add_parser("events", help="lista eventos gravados")
    ep.add_argument("--limit", type=int, default=30)
    ep.set_defaults(func=_cmd_events)

    tp = sub.add_parser("test-telegram", help="envia mensagem de teste")
    tp.set_defaults(func=_cmd_test_telegram)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if load_dotenv:
        load_dotenv()  # carrega o .env para os ${VAR} do config
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        cfg = Config.load(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Erro de config: {exc}", file=sys.stderr)
        return 2

    if not cfg.scope_confirmed:
        print(
            "⚠️  scope_confirmed=false no config.\n"
            "    Confirme que você é dono ou tem AUTORIZAÇÃO para monitorar os alvos\n"
            "    e ajuste 'scope_confirmed: true' no config.yaml para prosseguir.",
            file=sys.stderr,
        )
        return 3

    return asyncio.run(args.func(cfg, args))


if __name__ == "__main__":
    raise SystemExit(main())
