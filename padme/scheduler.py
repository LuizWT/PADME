"""Loop de monitoramento contínuo (modo listening).

Roda um scan de todos os alvos, aplica o diff, notifica no Telegram só o que
mudou, e dorme até a próxima varredura. O primeiro ciclo de um alvo novo grava
o baseline (sem spam de "tudo é novo").
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from .config import Config
from .engine import Engine, build_notifiers
from .heartbeat import from_config as heartbeat_from_config
from .levels import filter_events, parse_level
from .storage import Storage
from .notify import TelegramNotifier

log = logging.getLogger("padme")


async def _announce(notifiers: list, msg: str) -> None:
    for n in notifiers:
        await n.announce(msg)


async def _run_cycle(cfg: Config, engine: Engine, storage: Storage,
                     notifiers: list, level, cycle: int) -> bool:
    """Roda um ciclo (todos os alvos). Devolve True se todos varreram sem erro
    — é o `ok` do heartbeat: um ciclo com falha vira ping de falha."""
    cycle_ok = True
    for target in cfg.targets:
        first = not storage.is_known_target(target)
        try:
            result = await engine.scan_target(target)
            events = engine.apply(result)
        except Exception as exc:  # noqa: BLE001
            log.error("[%s] scan falhou: %s", target, exc)
            cycle_ok = False
            continue

        if first:
            log.info("[%s] baseline gravado (%d itens).", target, len(events))
        elif events:
            telegram_events = filter_events(events, level) if notifiers else []

            log.info(
                "[%s] %d mudança(s); %d no nível Telegram '%s'.",
                target,
                len(events),
                len(telegram_events),
                level.name.lower(),
            )

            for n in notifiers:
                if isinstance(n, TelegramNotifier):
                    enviar = telegram_events
                else:
                    enviar = events

                if enviar:
                    await n.notify_events(target, enviar)
        else:
            log.info("[%s] sem mudanças.", target)
    return cycle_ok


async def run_monitor(cfg: Config, once: bool = False) -> None:
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifiers = build_notifiers(cfg)
    heartbeat = heartbeat_from_config(cfg)
    interval = cfg.interval_seconds
    level = parse_level(cfg.telegram.level)

    if once:
        log.info("Ciclo único (--once): %d alvo(s), nível '%s'.",
                 len(cfg.targets), level.name.lower())
    else:
        await _announce(
            notifiers,
            f"modo sentinela — {len(cfg.targets)} alvo(s), varredura a cada "
            f"{interval}s, nível {level.name.lower()}.",
        )
        log.info(
            "Sentinela ativa: %d alvo(s), varredura a cada %ds, nível '%s'. Ctrl+C para parar.",
            len(cfg.targets), interval, level.name.lower(),
        )
    if heartbeat:
        log.info("Heartbeat ativo (a cada %d ciclo(s)%s).",
                 heartbeat.every_cycles, " + ping" if heartbeat.url else "")

    cycle = 0
    try:
        while True:
            cycle += 1
            cycle_ok = await _run_cycle(cfg, engine, storage, notifiers, level, cycle)
            if heartbeat:
                await heartbeat.beat(cycle, ok=cycle_ok)

            if once:
                log.info("Ciclo único concluído (%s).", "ok" if cycle_ok else "com falhas")
                break

            next_run = datetime.now() + timedelta(seconds=interval)
            log.info("Ciclo #%d %s. Próxima varredura às %s.",
                     cycle, "ok" if cycle_ok else "com falhas",
                     next_run.strftime("%H:%M:%S"))
            await asyncio.sleep(interval)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Encerrando sentinela.")
        await _announce(notifiers, "monitoramento encerrado.")
    finally:
        storage.close()
