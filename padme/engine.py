"""Orquestração: junta collectors, storage, diff e notificação.

Fluxo de um scan de um alvo:
  1. wildcard + subdomains -> descobre hosts
  2. para cada host (com concorrência limitada): dns, http, tls, takeover, ports
  3. consolida os Records E os escopos observados com sucesso
  4. storage.apply_scan -> devolve os eventos (o que mudou)

Confiabilidade: cada collector devolve um `CollectionResult` com `ok`. Só os
escopos observados autoritativamente (`ok=True`) entram em `observed_scopes` —
o diff só pode gerar REMOVED dentro deles, então um erro de coleta preserva o
estado em vez de fingir remoção.

Segurança: por padrão não seguimos redirects e não sondamos ativamente hosts
que resolvem para IP privado/reservado (anti-SSRF / rede interna).
"""

from __future__ import annotations

import asyncio
import logging
import socket

import httpx

from . import netpolicy
from .collectors import bruteforce, dns, http, ports, subdomains, takeover, tls, wildcard
from .config import Config
from .levels import Level, parse_level
from .models import CollectionResult, Event, Kind, Record, ScanResult
from .notify import DiscordNotifier, EmailNotifier, TelegramNotifier, WebhookNotifier
from .storage import Storage

log = logging.getLogger("padme")

_USER_AGENT = "Padme-ASM/0.1 (+attack-surface-monitor)"

# collector -> Kind do escopo (a "célula" onde ausência = remoção real)
_SCOPE_KIND = {
    "dns": Kind.DNS,
    "http": Kind.HTTP,
    "tls": Kind.TLS,        # cobre TLS e CERT_EXPIRY
    "takeover": Kind.TAKEOVER,
    "ports": Kind.PORT,
}


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
            # 0. curinga de DNS: se o apex responde a qualquer nome, a
            # enumeração ativa não é confiável — detecta e usa pra filtrar.
            wc = wildcard.Wildcard()
            if self.cfg.collectors.wildcard:
                try:
                    wc = await wildcard.detect(
                        target, self.cfg.timeout, self.cfg.collectors.wildcard_probes)
                    # detecção concluiu -> escopo observado (mesmo se não houver curinga)
                    result.observed_scopes.add((Kind.WILDCARD.value, target))
                    if wc.active:
                        log.info("[%s] wildcard DNS ativo (confiança %.0f%%) -> %s",
                                 target, wc.confidence * 100, ", ".join(sorted(wc.ips)))
                        result.records.append(
                            Record(Kind.WILDCARD, target, ", ".join(sorted(wc.ips)))
                        )
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"wildcard: {exc}")

            # 1. subdomínios
            hosts: set[str] = {target}
            if self.cfg.collectors.subdomains:
                try:
                    cr = await subdomains.collect(target, client)
                    result.records.extend(cr.records)
                    hosts |= cr.hosts
                    if cr.ok:  # alguma fonte CT respondeu -> escopo observado
                        result.observed_scopes.add((Kind.SUBDOMAIN.value, target))
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"subdomains: {exc}")
            if self.cfg.collectors.bruteforce:
                try:
                    words = bruteforce.load_words(self.cfg.collectors.wordlist)
                    cr = await bruteforce.collect(
                        target, words, self.cfg.timeout, self.cfg.concurrency, wildcard=wc)
                    result.records.extend(cr.records)
                    hosts |= cr.hosts
                    # bruteforce é suplementar: NÃO marca o escopo de subdomínio
                except FileNotFoundError as exc:
                    # wordlist configurada e ausente: sinal claro, não silêncio
                    log.warning("[%s] bruteforce pulado: %s", target, exc)
                    result.errors.append(f"bruteforce: {exc}")
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"bruteforce: {exc}")
            log.info("[%s] %d host(s) para inspecionar", target, len(hosts))

            # 2. host-level (concorrente)
            tasks = [self._scan_host(h, client, result) for h in sorted(hosts)]
            await asyncio.gather(*tasks)

        # 3. qualidade de sinal: marca subdomínio como live (tem serviço) ou quiet
        result.records = annotate_liveness(result.records)
        return result

    async def _scan_host(
        self, host: str, client: httpx.AsyncClient, result: ScanResult
    ) -> None:
        async with self._sem:
            col = self.cfg.collectors
            net = self.cfg.network
            body_cache: dict[str, str] = {}  # GET reaproveitado entre http e takeover
            host_ips: set[str] = set()

            # DNS primeiro (passivo) — também dá os IPs pra trava de IP privado
            if col.dns:
                cr = await _safe(dns.collect_host(host, self.cfg.timeout), host, "dns", result)
                _absorb(cr, result, "dns", host)
                host_ips = _ips_from_dns(cr.records)

            # trava anti-SSRF/rede interna: não sonda ativamente IP privado/reservado
            active = col.http or col.tls or col.takeover or col.ports
            if active and not net.allow_private_ips:
                ips = host_ips or await _resolve_ips_quick(host, self.cfg.timeout)
                if ips and netpolicy.any_disallowed(ips):
                    log.debug(
                        "[%s] resolve p/ IP privado/reservado (%s) — sonda ativa pulada "
                        "(network.allow_private_ips=false)", host, ", ".join(sorted(ips)))
                    return  # escopos ativos não marcados -> estado preservado

            if col.http:
                cr = await _safe(
                    http.collect_host(host, client, body_cache, net.follow_redirects,
                                      col.max_response_bytes),
                    host, "http", result)
                _absorb(cr, result, "http", host)
            if col.tls:
                cr = await _safe(
                    tls.collect_host(host, self.cfg.timeout, cert_expiry_days=col.cert_expiry_days),
                    host, "tls", result)
                _absorb(cr, result, "tls", host)
            if col.takeover:
                cr = await _safe(
                    takeover.collect_host(host, client, self.cfg.timeout, body_cache,
                                          net.follow_redirects, col.max_response_bytes),
                    host, "takeover", result)
                _absorb(cr, result, "takeover", host)
            if col.ports:
                cr = await _safe(
                    ports.collect_host(host, col.ports_list, self.cfg.timeout),
                    host, "ports", result)
                _absorb(cr, result, "ports", host)

    def apply(self, result: ScanResult) -> list[Event]:
        return self.storage.apply_scan(
            result.target, result.records, observed_scopes=result.observed_scopes
        )


async def _safe(coro, host: str, name: str, result: ScanResult) -> CollectionResult:
    """Executa um collector com rede protegida. Exceção inesperada -> ok=False
    (na dúvida, preserva o estado) e registra o erro."""
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"{name}[{host}]: {exc}")
        return CollectionResult(records=[], ok=False, error=str(exc))


def _absorb(cr: CollectionResult, result: ScanResult, name: str, host: str) -> None:
    """Junta os records e, se a coleta foi autoritativa, marca o escopo observado."""
    result.records.extend(cr.records)
    if cr.ok:
        scope_kind = _SCOPE_KIND[name]
        result.observed_scopes.add((scope_kind.value, host))


def _ips_from_dns(records: list[Record]) -> set[str]:
    """Extrai os IPs (A/AAAA) já coletados pelo collector de DNS."""
    ips: set[str] = set()
    for r in records:
        if r.kind == Kind.DNS and ("|A|" in r.key or "|AAAA|" in r.key):
            ips.add(r.value)
    return ips


async def _resolve_ips_quick(host: str, timeout: float) -> set[str]:
    """Resolve A/AAAA rapidamente (usado só quando o collector DNS está off e
    ainda precisamos checar a política de IP privado)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=timeout)
    except Exception:  # noqa: BLE001
        return set()
    return {info[4][0] for info in infos}


def annotate_liveness(records: list[Record]) -> list[Record]:
    """Marca cada subdomínio como 'live' (tem HTTP/TLS/porta viva no scan) ou
    'quiet' (só resolve em DNS). Reduz ruído: alerta vira 'alvo vivo', não só
    'existe um nome'. Um 'quiet -> live' futuro é sinal de host que acordou."""
    live: set[str] = set()
    for r in records:
        if r.kind == Kind.HTTP:
            live.add(r.key.split("://", 1)[-1].split("/", 1)[0])
        elif r.kind in (Kind.TLS, Kind.PORT):
            live.add(r.key.rsplit(":", 1)[0])

    out: list[Record] = []
    for r in records:
        if r.kind == Kind.SUBDOMAIN:
            out.append(Record(Kind.SUBDOMAIN, r.key, "live" if r.key in live else "quiet"))
        else:
            out.append(r)
    return out


def build_notifiers(cfg: Config) -> list:
    """Monta a lista de canais ativos, cada um com seu próprio limiar de nível
    (severidade por canal). O terminal sempre mostra tudo; cada canal decide o
    que recebe."""
    out: list = []

    tg = cfg.telegram
    if tg.enabled:
        n = TelegramNotifier(tg.bot_token, tg.chat_id, level=parse_level(tg.level))
        if n.configured:
            out.append(n)
        else:
            log.warning("Telegram habilitado mas token/chat_id ausentes — ignorado.")

    dc = cfg.discord
    if dc.enabled:
        if dc.webhook_url:
            out.append(DiscordNotifier(dc.webhook_url, level=parse_level(dc.level)))
        else:
            log.warning("Discord habilitado mas webhook_url ausente — ignorado.")

    wh = cfg.webhook
    if wh.enabled:
        if wh.url:
            out.append(WebhookNotifier(wh.url, level=parse_level(wh.level, Level.DEBUG),
                                       headers=wh.headers))
        else:
            log.warning("Webhook habilitado mas url ausente — ignorado.")

    em = cfg.email
    if em.enabled:
        n = EmailNotifier(em.smtp_host, em.smtp_port, em.username, em.password,
                          em.from_addr, em.to, em.use_tls, level=parse_level(em.level))
        if n.configured:
            out.append(n)
        else:
            log.warning("E-mail habilitado mas smtp_host/from/to ausentes — ignorado.")

    return out
