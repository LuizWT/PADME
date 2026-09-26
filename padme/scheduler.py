"""Loop de monitoramento contínuo (modo listening).

Roda um scan de todos os alvos, aplica o diff, notifica só o que mudou (cada
canal pelo seu próprio nível), e dorme até a próxima varredura. O primeiro
ciclo de um alvo novo grava o baseline (sem spam de "tudo é novo" e sem poluir
o histórico).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from .config import Config
from .engine import Engine, build_notifiers
from .heartbeat import from_config as heartbeat_from_config
from .notify import send_all
from .storage import Storage

log = logging.getLogger("padme")


async def _announce(notifiers: list, msg: str) -> None:
    for n in notifiers:
        try:
            await n.announce(msg)
        except Exception as exc:  # noqa: BLE001 — anúncio nunca derruba o loop
            log.debug("announce falhou (%s): %s", getattr(n, "name", "?"), exc)


async def _run_cycle(cfg: Config, engine: Engine, storage: Storage,
                     notifiers: list, cycle: int) -> bool:
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
            log.info("[%s] baseline gravado (%d itens no estado).", target, len(result.records))
        elif events:
            log.info("[%s] %d mudança(s).", target, len(events))
            if notifiers:
                await send_all(notifiers, target, events)
        else:
            log.info("[%s] sem mudanças.", target)
    return cycle_ok


async def run_monitor(cfg: Config, once: bool = False) -> None:
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifiers = build_notifiers(cfg)
    heartbeat = heartbeat_from_config(cfg)
    interval = cfg.interval_seconds

    if once:
        log.info("Ciclo único (--once): %d alvo(s).", len(cfg.targets))
    else:
        await _announce(
            notifiers,
            f"modo sentinela — {len(cfg.targets)} alvo(s), varredura a cada {interval}s.",
        )
        log.info(
            "Sentinela ativa: %d alvo(s), varredura a cada %ds. Ctrl+C para parar.",
            len(cfg.targets), interval,
        )
    if heartbeat:
        log.info("Heartbeat ativo (a cada %d ciclo(s)%s).",
                 heartbeat.every_cycles, " + ping" if heartbeat.url else "")

    cycle = 0
    try:
        while True:
            cycle += 1
            cycle_ok = await _run_cycle(cfg, engine, storage, notifiers, cycle)
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
