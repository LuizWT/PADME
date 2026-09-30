"""Loop de monitoramento contínuo (modo listening).

Roda um scan de todos os alvos, aplica o diff, notifica só o que mudou (cada
canal pelo seu próprio nível), e dorme até a próxima varredura. O primeiro
ciclo de um alvo novo grava o baseline (sem spam de "tudo é novo" e sem poluir
o histórico).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta

from .alerts import damp_flapping
from .config import Config
from .engine import Engine, build_notifiers, summarize_health
from .heartbeat import from_config as heartbeat_from_config
from .notify import NotificationManager
from .storage import Storage

log = logging.getLogger("padme")


async def _run_cycle(cfg: Config, engine: Engine, storage: Storage,
                     notifier: NotificationManager, cycle: int) -> bool:
    """Roda um ciclo (todos os alvos). Devolve `scan_ok`: o dead-man's switch
    monitora ALIVENESS (o loop rodou e varreu), então só uma exceção FATAL de
    scan derruba o heartbeat. Coleta parcial e falha de notificação são
    registradas e logadas separadamente (saúde de coleta ≠ saúde de notificação
    ≠ heartbeat), mas NÃO viram ping de falha."""
    scan_ok = True
    for target in cfg.targets:
        first = not storage.is_known_target(target)
        t0 = time.monotonic()
        try:
            result = await engine.scan_target(target)
            events = engine.apply(result)
        except Exception as exc:  # noqa: BLE001
            log.error("[%s] scan falhou: %s", target, exc)
            scan_ok = False
            continue

        errs = len(result.errors)
        storage.update_health(target, error_count=errs, partial=errs > 0,
                              duration_ms=int((time.monotonic() - t0) * 1000),
                              collectors=summarize_health(result),
                              inconclusive=result.inconclusive)
        if errs:
            log.warning("[%s] coleta PARCIAL: %d erro(s) de collector (estado preservado).",
                        target, errs)

        if first and not storage.is_known_target(target):
            log.info("[%s] baseline PROVISÓRIA (coleta incompleta): consolida no próximo "
                     "ciclo, sem gerar eventos.", target)
        elif first:
            log.info("[%s] baseline gravado (%d itens no estado).", target, len(result.records))
        elif events:
            to_notify, flapped = damp_flapping(
                storage, target, events, cfg.alerts.flap_threshold, cfg.alerts.flap_window_minutes)
            log.info("[%s] %d mudança(s)%s.", target, len(events),
                     f"; {flapped} suprimida(s) por flapping" if flapped else "")
            if notifier and to_notify:
                results = await notifier.dispatch(target, to_notify)
                failed = [r for r in results if not r.ok]
                if failed:
                    log.warning("[%s] notificação falhou em %d canal(is): %s", target,
                                len(failed), ", ".join(r.channel for r in failed))
        else:
            log.info("[%s] sem mudanças.", target)
    return scan_ok


async def run_monitor(cfg: Config, once: bool = False) -> None:
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifier = NotificationManager(build_notifiers(cfg))
    heartbeat = heartbeat_from_config(cfg)
    interval = cfg.interval_seconds

    if once:
        log.info("Ciclo único (--once): %d alvo(s).", len(cfg.targets))
    else:
        await notifier.announce(
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
            cycle_ok = await _run_cycle(cfg, engine, storage, notifier, cycle)
            if heartbeat:
                await heartbeat.beat(cycle, ok=cycle_ok)

            pruned = storage.prune_events(cfg.storage.event_retention_days)
            if pruned:
                log.info("Retenção: %d evento(s) antigos removidos (> %dd).",
                         pruned, cfg.storage.event_retention_days)

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
        await notifier.announce("monitoramento encerrado.")
    finally:
        storage.close()
