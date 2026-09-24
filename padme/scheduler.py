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
from .levels import filter_events, parse_level
from .storage import Storage

log = logging.getLogger("padme")


async def _announce(notifiers: list, msg: str) -> None:
    for n in notifiers:
        await n.announce(msg)


async def run_monitor(cfg: Config) -> None:
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifiers = build_notifiers(cfg)
    interval = cfg.interval_seconds
    level = parse_level(cfg.telegram.level)

    await _announce(
        notifiers,
        f"modo sentinela — {len(cfg.targets)} alvo(s), varredura a cada "
        f"{interval}s, nível {level.name.lower()}.",
    )
    log.info(
        "Sentinela ativa: %d alvo(s), varredura a cada %ds, nível '%s'. Ctrl+C para parar.",
        len(cfg.targets),
        interval,
        level.name.lower(),
    )

    cycle = 0
    try:
        while True:
            cycle += 1
            for target in cfg.targets:
                first = not storage.is_known_target(target)
                try:
                    result = await engine.scan_target(target)
                    events = engine.apply(result)
                except Exception as exc:  # noqa: BLE001
                    log.error("[%s] scan falhou: %s", target, exc)
                    continue

                if first:
                    log.info("[%s] baseline gravado (%d itens).", target, len(events))
                elif events:
                    enviar = filter_events(events, level) if notifiers else []
                    log.info("[%s] %d mudança(s); %d no nível '%s'.",
                             target, len(events), len(enviar), level.name.lower())
                    for n in notifiers:
                        await n.notify_events(target, enviar)
                else:
                    log.info("[%s] sem mudanças.", target)

            next_run = datetime.now() + timedelta(seconds=interval)
            log.info("Ciclo #%d ok. Próxima varredura às %s.", cycle, next_run.strftime("%H:%M:%S"))
            await asyncio.sleep(interval)
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Encerrando sentinela.")
        await _announce(notifiers, "monitoramento encerrado.")
    finally:
        storage.close()
