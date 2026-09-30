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
import time

import httpx

from . import netpolicy, ratelimit
from .collectors import (
    bruteforce,
    dns,
    dnsrecon,
    favicon,
    http,
    ports,
    subdomains,
    takeover,
    tls,
    wildcard,
)
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
    "http": Kind.HTTP,      # cobre HTTP e HTTPSEC (postura vem da mesma resposta)
    "favicon": Kind.FAVICON,
    "tls": Kind.TLS,        # cobre TLS e CERT_EXPIRY
    "takeover": Kind.TAKEOVER,
    "ports": Kind.PORT,
}


class Engine:
    def __init__(self, config: Config, storage: Storage):
        self.cfg = config
        self.storage = storage
        self._sem = asyncio.Semaphore(config.concurrency)
        self._rate = ratelimit.from_config(config)  # pacing responsável (§12)

    async def _pace(self, request: "httpx.Request") -> None:
        """Hook de requisição do httpx: aplica o rate-limit antes de cada envio
        (cobre todos os collectors que usam o client). No-op se desligado."""
        await self._rate.acquire(request.url.host)

    async def scan_target(self, target: str) -> ScanResult:
        result = ScanResult(target=target)
        t0 = time.monotonic()
        log.debug("[%s] scan iniciado", target)
        # subdomínios já conhecidos (valor = live/quiet anterior): continuam sendo
        # inspecionados mesmo se a descoberta falhar, e só saem do estado com
        # prova de DNS (ver carry_forward_subdomains).
        known_subs = {key: value for (kind, key), value in self.storage.load_state(target).items()
                      if kind == Kind.SUBDOMAIN.value}
        # teto de connects de porta simultâneos no scan inteiro (todos os hosts)
        self._connect_limit = asyncio.Semaphore(self.cfg.network.max_parallel_connects)
        limits = httpx.Limits(max_connections=self.cfg.concurrency)
        headers = {"User-Agent": _USER_AGENT}

        # transporte com retry educado em 429/5xx transitório (§12); verify=False
        # e limits vão no transporte (ignorados no client quando há transport custom).
        transport = ratelimit.RetryTransport(
            httpx.AsyncHTTPTransport(verify=False, limits=limits, retries=0),
            max_retries=self.cfg.network.max_retries,
        )
        async with httpx.AsyncClient(
            timeout=self.cfg.timeout,
            headers=headers,
            transport=transport,
            event_hooks={"request": [self._pace]},  # pacing responsável (§12)
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
                    result.mark_collector("wildcard", True)
                    if wc.active:
                        log.info("[%s] wildcard DNS ativo (confiança %.0f%%) -> %s",
                                 target, wc.confidence * 100, ", ".join(sorted(wc.ips)))
                        result.records.append(
                            Record(Kind.WILDCARD, target, ", ".join(sorted(wc.ips)))
                        )
                except Exception as exc:  # noqa: BLE001
                    result.mark_collector("wildcard", False)
                    result.errors.append(f"wildcard: {exc}")

            # 0b. sinais RED no apex: NS (delegação/hijack) + SPF/DMARC (spoofing)
            if self.cfg.collectors.dns_records:
                try:
                    cr = await dnsrecon.collect(target, self.cfg.timeout)
                    result.records.extend(cr.records)
                    result.mark_collector("dnsrecon", cr.ok)
                    result.inconclusive += not cr.ok
                    if cr.ok:  # observação autoritativa -> escopos podem gerar REMOVED
                        result.observed_scopes.add((Kind.NS.value, target))
                        result.observed_scopes.add((Kind.MAILSEC.value, target))
                except Exception as exc:  # noqa: BLE001
                    result.mark_collector("dnsrecon", False)
                    result.errors.append(f"dnsrecon: {exc}")

            # 1. subdomínios
            hosts: set[str] = {target}
            if self.cfg.collectors.subdomains:
                try:
                    cr = await subdomains.collect(target, client)
                    result.records.extend(cr.records)
                    hosts |= cr.hosts
                    result.mark_collector("subdomains", cr.ok)
                    result.inconclusive += not cr.ok
                    if cr.ok:  # alguma fonte CT respondeu -> escopo observado
                        result.observed_scopes.add((Kind.SUBDOMAIN.value, target))
                except Exception as exc:  # noqa: BLE001
                    result.mark_collector("subdomains", False)
                    result.errors.append(f"subdomains: {exc}")
            if self.cfg.collectors.bruteforce:
                try:
                    words = bruteforce.load_words(self.cfg.collectors.wordlist)
                    cr = await bruteforce.collect(
                        target, words, self.cfg.timeout, self.cfg.concurrency, wildcard=wc,
                        pace=self._rate.acquire)
                    result.records.extend(cr.records)
                    hosts |= cr.hosts
                    result.mark_collector("bruteforce", cr.ok)
                    result.inconclusive += not cr.ok
                    # bruteforce é suplementar: NÃO marca o escopo de subdomínio
                except FileNotFoundError as exc:
                    # wordlist configurada e ausente: sinal claro, não silêncio
                    log.warning("[%s] bruteforce pulado: %s", target, exc)
                    result.mark_collector("bruteforce", False)
                    result.errors.append(f"bruteforce: {exc}")
                except Exception as exc:  # noqa: BLE001
                    result.mark_collector("bruteforce", False)
                    result.errors.append(f"bruteforce: {exc}")
            hosts |= set(known_subs)  # conhecidos seguem monitorados mesmo sem descoberta
            log.info("[%s] %d host(s) para inspecionar", target, len(hosts))

            # 2. host-level (concorrente)
            tasks = [self._scan_host(h, client, result) for h in sorted(hosts)]
            await asyncio.gather(*tasks)

        # 3. subdomínio conhecido que a descoberta não trouxe só sai com prova de DNS
        result.records = carry_forward_subdomains(
            result.records, result.observed_scopes, known_subs)
        # a partir daqui toda ausência de subdomínio foi provada pelo DNS
        # (o resto foi mantido acima), então o escopo pode gerar REMOVED.
        result.observed_scopes.add((Kind.SUBDOMAIN.value, target))

        # 4. qualidade de sinal: live (tem serviço) ou quiet — só muda com prova
        result.records = annotate_liveness(
            result.records, result.observed_scopes, known_subs, self._live_kinds())
        log.info("[%s] scan concluído: %d host(s), %d record(s), %d erro(s), %dms",
                 target, len(hosts), len(result.records), len(result.errors),
                 int((time.monotonic() - t0) * 1000))
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

            http_ok = False
            if col.http:
                cr = await _safe(
                    http.collect_host(host, client, body_cache, net.follow_redirects,
                                      col.max_response_bytes, col.http_security,
                                      allow_private=net.allow_private_ips),
                    host, "http", result)
                _absorb(cr, result, "http", host)
                http_ok = cr.ok
            # favicon: 1 GET extra, só p/ host que respondeu HTTP (não sonda morto)
            if col.favicon and http_ok:
                cr = await _safe(
                    favicon.collect_host(host, client, net.follow_redirects,
                                         col.max_response_bytes,
                                         allow_private=net.allow_private_ips),
                    host, "favicon", result)
                _absorb(cr, result, "favicon", host)
            if col.tls:
                cr = await _safe(
                    tls.collect_host(host, self.cfg.timeout, cert_expiry_days=col.cert_expiry_days,
                                     pace=self._rate.acquire),
                    host, "tls", result)
                _absorb(cr, result, "tls", host)
            if col.takeover:
                cr = await _safe(
                    takeover.collect_host(host, client, self.cfg.timeout, body_cache,
                                          net.follow_redirects, col.max_response_bytes,
                                          allow_private=net.allow_private_ips),
                    host, "takeover", result)
                _absorb(cr, result, "takeover", host)
            if col.ports:
                cr = await _safe(
                    ports.collect_host(host, col.ports_list, self.cfg.timeout, col.ports_banner,
                                       pace=self._rate.acquire, limit=self._connect_limit),
                    host, "ports", result)
                _absorb(cr, result, "ports", host)

    def _live_kinds(self) -> tuple[Kind, ...]:
        """Escopos ativos ligados que sustentam 'live' (HTTP/TLS/portas)."""
        col = self.cfg.collectors
        return tuple(k for k, on in ((Kind.HTTP, col.http), (Kind.TLS, col.tls),
                                     (Kind.PORT, col.ports)) if on)

    def apply(self, result: ScanResult) -> list[Event]:
        return self.storage.apply_scan(
            result.target, result.records, observed_scopes=result.observed_scopes,
            source=self.cfg.source, context_rules=self.cfg.context.assets,
            complete=result.complete,
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
    """Junta os records e, se a coleta foi autoritativa, marca o escopo observado.
    `ok=False` sem `error` é coleta INCONCLUSIVA (timeout, sem resposta); com
    `error` veio de exceção (`_safe`) e já está em `result.errors`."""
    result.records.extend(cr.records)
    result.mark_collector(name, cr.ok)
    if not cr.ok and not cr.error:
        result.inconclusive += 1
    if cr.ok:
        scope_kind = _SCOPE_KIND[name]
        result.observed_scopes.add((scope_kind.value, host))


def summarize_health(result: ScanResult) -> dict[str, dict]:
    """Consolida collector_stats em status por collector (§7 do roadmap):
    ok (só sucesso) · partial (mistura) · error (só falha). Vazio se não rodou."""
    out: dict[str, dict] = {}
    for name, s in sorted(result.collector_stats.items()):
        ok, fail = s.get("ok", 0), s.get("fail", 0)
        if ok and not fail:
            status = "ok"
        elif ok and fail:
            status = "partial"
        elif fail and not ok:
            status = "error"
        else:
            continue
        out[name] = {"status": status, "ok": ok, "fail": fail}
    return out


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


def _dns_hosts(records: list[Record]) -> set[str]:
    """Hosts com algum registro DNS neste scan."""
    return {r.key.split("|", 1)[0] for r in records if r.kind == Kind.DNS}


def _dns_gone(host: str, observed: set[tuple[str, str]], dns_hosts: set[str]) -> bool:
    """O nome deixou de resolver: DNS observado com sucesso e sem nenhum registro
    (NXDOMAIN / sem A, AAAA, CNAME ou MX). É a prova usada para "sumiu"."""
    return (Kind.DNS.value, host) in observed and host not in dns_hosts


def carry_forward_subdomains(records: list[Record], observed: set[tuple[str, str]],
                             known: dict[str, str]) -> list[Record]:
    """Subdomínio já conhecido que a descoberta NÃO trouxe neste scan é mantido,
    a menos que o DNS dele tenha sido observado e o nome não resolva mais.

    Ausência na descoberta não é remoção: o CT pode cair ou voltar vazio, o
    bruteforce trata timeout como "não resolve" e pode ser desligado. Só o DNS do
    próprio host diz, com autoridade, que o nome deixou de existir."""
    present = {r.key for r in records if r.kind == Kind.SUBDOMAIN}
    dns_hosts = _dns_hosts(records)
    out = list(records)
    for host, value in sorted(known.items()):
        if host not in present and not _dns_gone(host, observed, dns_hosts):
            out.append(Record(Kind.SUBDOMAIN, host, value))
    return out


def annotate_liveness(records: list[Record],
                      observed: set[tuple[str, str]] | None = None,
                      previous: dict[str, str] | None = None,
                      live_kinds: tuple[Kind, ...] = (Kind.HTTP, Kind.TLS, Kind.PORT),
                      ) -> list[Record]:
    """Marca cada subdomínio como 'live' (tem HTTP/TLS/porta viva no scan) ou
    'quiet' (só resolve em DNS). Reduz ruído: alerta vira 'alvo vivo', não só
    'existe um nome'. Um 'quiet -> live' futuro é sinal de host que acordou.

    'live' vem de evidência positiva. 'quiet' exige evidência NEGATIVA
    autoritativa: o nome deixou de resolver, ou todos os collectors ativos
    ligados observaram o host sem achar nada. Sem isso (timeout, host pulado por
    IP privado) o valor anterior é mantido — senão um timeout de HTTP viraria um
    `live -> quiet` falso enquanto o estado HTTP do host segue preservado.

    Sem `observed` (compat), ausência de serviço conta como 'quiet'."""
    live: set[str] = set()
    for r in records:
        if r.kind == Kind.HTTP:
            live.add(r.key.split("://", 1)[-1].split("/", 1)[0])
        elif r.kind in (Kind.TLS, Kind.PORT):
            live.add(r.key.rsplit(":", 1)[0])
    dns_hosts = _dns_hosts(records)
    prev = previous or {}

    def quiet_proven(host: str) -> bool:
        if _dns_gone(host, observed, dns_hosts):
            return True
        return bool(live_kinds) and all((k.value, host) in observed for k in live_kinds)

    out: list[Record] = []
    for r in records:
        if r.kind != Kind.SUBDOMAIN:
            out.append(r)
            continue
        if r.key in live:
            value = "live"
        elif observed is None or quiet_proven(r.key):
            value = "quiet"
        else:
            value = prev.get(r.key) or "quiet"
        out.append(Record(Kind.SUBDOMAIN, r.key, value, metadata=r.metadata))
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
