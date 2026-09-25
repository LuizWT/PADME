"""Orquestração: junta collectors, storage, diff e notificação.

Fluxo de um scan de um alvo:
  1. subdomains -> descobre hosts
  2. para cada host (com concorrência limitada): dns, http, tls, ports
  3. consolida os Records
  4. storage.apply_scan -> devolve os eventos (o que mudou)
  5. (se houver mudança e for monitor) notifica no Telegram
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from .collectors import dns, http, ports, subdomains, takeover, tls
from .config import Config
from .models import Event, Record, ScanResult
from .notify import DiscordNotifier, TelegramNotifier, WebhookNotifier
from .storage import Storage

log = logging.getLogger("padme")

_USER_AGENT = "Padme-ASM/0.1 (+attack-surface-monitor)"


class Engine:
    def __init__(self, config: Config, storage: Storage):
        self.cfg = config
        self.storage = storage
        self._sem = asyncio.Semaphore(config.concurrency)

    async def scan_target(self, target: str) -> ScanResult:
        result = ScanResult(target=target)
        limits = httpx.Limits(max_connections=self.cfg.concurrency)
        headers = {"User-Agent": _USER_AGENT}

        async with httpx.AsyncClient(
            timeout=self.cfg.timeout,
            headers=headers,
            limits=limits,
            verify=False,  # queremos observar hosts mesmo com TLS quebrado
        ) as client:
            # 1. subdomínios
            hosts: set[str] = {target}
            if self.cfg.collectors.subdomains:
                try:
                    sub_records, hosts = await subdomains.collect(target, client)
                    result.records.extend(sub_records)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"subdomains: {exc}")
            log.info("[%s] %d host(s) para inspecionar", target, len(hosts))

            # 2. host-level (concorrente)
            tasks = [self._scan_host(h, client, result) for h in sorted(hosts)]
            await asyncio.gather(*tasks)

        return result

    async def _scan_host(
        self, host: str, client: httpx.AsyncClient, result: ScanResult
    ) -> None:
        async with self._sem:
            col = self.cfg.collectors
            if col.dns:
                result.records.extend(await _safe(dns.collect_host(host, self.cfg.timeout), host, "dns", result))
            if col.http:
                result.records.extend(await _safe(http.collect_host(host, client), host, "http", result))
            if col.tls:
                result.records.extend(await _safe(
                    tls.collect_host(host, self.cfg.timeout, cert_expiry_days=col.cert_expiry_days),
                    host, "tls", result))
            if col.takeover:
                result.records.extend(
                    await _safe(takeover.collect_host(host, client, self.cfg.timeout), host, "takeover", result)
                )
            if col.ports:
                result.records.extend(
                    await _safe(ports.collect_host(host, col.ports_list, self.cfg.timeout), host, "ports", result)
                )

    def apply(self, result: ScanResult) -> list[Event]:
        return self.storage.apply_scan(result.target, result.records)


async def _safe(coro, host: str, name: str, result: ScanResult) -> list[Record]:
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"{name}[{host}]: {exc}")
        return []


def build_notifiers(cfg: Config) -> list:
    """Monta a lista de canais ativos (Telegram, Discord, webhook)."""
    out: list = []

    tg = cfg.telegram
    if tg.enabled:
        n = TelegramNotifier(tg.bot_token, tg.chat_id)
        if n.configured:
            out.append(n)
        else:
            log.warning("Telegram habilitado mas token/chat_id ausentes — ignorado.")

    dc = cfg.discord
    if dc.enabled:
        if dc.webhook_url:
            out.append(DiscordNotifier(dc.webhook_url))
        else:
            log.warning("Discord habilitado mas webhook_url ausente — ignorado.")

    wh = cfg.webhook
    if wh.enabled:
        if wh.url:
            out.append(WebhookNotifier(wh.url))
        else:
            log.warning("Webhook habilitado mas url ausente — ignorado.")

    return out
