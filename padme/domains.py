"""Disponibilidade de um domínio registrável: dá para um atacante registrar?

Usado por dois detectores que compartilham a mesma pergunta:
  - takeover (CNAME dangling): o alvo do CNAME aponta para um domínio livre;
  - postura de e-mail: um `include:`/`redirect=` de SPF aponta para um domínio
    livre — quem registrar passa a autorizar envio em nome do alvo.

Dois sinais, do barato ao caro (o segundo é opcional):
  1. NS no DNS: NXDOMAIN no domínio registrável = FORA DA ZONA do TLD (não
     registrado OU expirado/suspenso, o DNS não distingue). NOERROR = a zona
     existe (registrado e ativo).
  2. RDAP (RFC 9082, opcional): separa "nunca registrado" (HTTP 404) de
     "registrado mas a caminho de liberar" (status pendingDelete/redemption/
     hold). Só com RDAP a confiança sobe para CONFIRMED (livre de fato).

Tudo aqui é determinístico e injeta a E/S (DNS e HTTP), então as regras são
puras e testáveis. Qualquer incerteza vira UNKNOWN -> quem chama preserva o
estado anterior (um erro de rede nunca "cria" nem "apaga" um achado).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Awaitable, Callable

import httpx
from publicsuffixlist import PublicSuffixList

log = logging.getLogger("padme")

IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


class Availability(str, Enum):
    FREE = "free"                # RDAP 404: registrável AGORA (confiança máxima)
    PENDING_RELEASE = "pending"  # RDAP: hold/redemption/pendingDelete -> vai liberar
    OUT_OF_ZONE = "out_of_zone"  # NS NXDOMAIN, RDAP não esclareceu: livre OU expirado
    REGISTERED = "registered"    # registrado e ativo -> terceiro NÃO reivindica
    UNKNOWN = "unknown"          # inconclusivo -> preserva o estado anterior


# EPP/RDAP status (RFC 8056/9083) que significam "o domínio está a caminho de
# ficar livre": comparados sem espaço/caixa.
_RELEASE_STATUSES = {
    "pendingdelete", "redemptionperiod", "clienthold", "serverhold",
    "pendingrestore", "inactive", "autorenewperiod", "redemption",
}


def _norm(status: str) -> str:
    return "".join(status.lower().split())


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    """Public Suffix List só com a seção ICANN: a pergunta é "dá para REGISTRAR
    este domínio num registro público?". Sufixos privados (herokuapp.com,
    github.io…) são recursos de plataforma, não registros — ficam com a base de
    fingerprints. `accept_unknown=False`: TLD fora da lista (.local, .internal,
    .test, .corp) não é registrável por ninguém."""
    return PublicSuffixList(only_icann=True, accept_unknown=False)


def registrable_domain(name: str) -> str | None:
    """Domínio registrável (sufixo público ICANN + 1 rótulo), pela PSL. None
    quando o nome não tem domínio registrável: TLD desconhecido/reservado ou o
    próprio nome já é um sufixo público (ex.: `co.uk`)."""
    name = (name or "").lower().rstrip(".")
    return _psl().privatesuffix(name) if name else None


def is_claimable(av: Availability) -> bool:
    """O domínio pode cair na mão de um atacante (gera achado)? FREE/pending/
    out-of-zone sim; REGISTERED não; UNKNOWN não decide (preserva)."""
    return av in (Availability.FREE, Availability.PENDING_RELEASE, Availability.OUT_OF_ZONE)


# ── RDAP (parsing puro) ───────────────────────────────────────────────────────
def rdap_base_for(tld: str, services: list) -> str | None:
    """Base RDAP de um TLD a partir do bootstrap da IANA (data.iana.org/rdap/
    dns.json). `services` = [[[tlds...], [urls...]], ...]. Prefere URL https e
    garante a barra final. None se o TLD não tem servidor RDAP."""
    tld = tld.lower().rstrip(".")
    for entry in services:
        try:
            tlds, urls = entry[0], entry[1]
        except (IndexError, TypeError):
            continue
        if tld in {t.lower() for t in tlds}:
            https = [u for u in urls if u.startswith("https://")] or list(urls)
            if https:
                return https[0] if https[0].endswith("/") else https[0] + "/"
    return None


def rdap_availability(status_code: int, body: dict | None) -> Availability:
    """Interpreta a resposta RDAP de /domain/<d>: 404 = livre; 200 com status de
    liberação = pending; 200 sem = registrado; o resto = inconclusivo."""
    if status_code == 404:
        return Availability.FREE
    if status_code == 200 and isinstance(body, dict):
        statuses = {_norm(s) for s in (body.get("status") or []) if isinstance(s, str)}
        if statuses & _RELEASE_STATUSES:
            return Availability.PENDING_RELEASE
        return Availability.REGISTERED
    return Availability.UNKNOWN


# ── checagem completa (DNS + RDAP opcional), com E/S injetada ─────────────────
@dataclass(frozen=True)
class DomainCheck:
    registrable: str | None
    availability: Availability


# ns_nxdomain(domínio) -> True (NXDOMAIN) | False (existe) | None (inconclusivo)
NsNxdomain = Callable[[str], Awaitable["bool | None"]]
# rdap(domínio registrável) -> Availability (nunca levanta; erro vira UNKNOWN)
Rdap = Callable[[str], Awaitable[Availability]]


async def check_registrable(name: str, ns_nxdomain: NsNxdomain,
                            rdap: Rdap | None = None) -> DomainCheck:
    """Disponibilidade do domínio registrável de `name`. Combina o NS (barato,
    sempre) com o RDAP (opcional, só refina). Regras:

      - sem domínio registrável (TLD interno/reservado) -> REGISTERED (ninguém
        de fora reivindica);
      - NS inconclusivo -> UNKNOWN (preserva);
      - zona existe (NS NOERROR): REGISTERED, a menos que o RDAP ache um status
        de liberação (expira mas o NS ainda está lá);
      - fora da zona (NS NXDOMAIN): FREE/PENDING conforme o RDAP; se o RDAP
        falhar/estiver ausente, OUT_OF_ZONE (livre OU expirado — ainda é risco);
        se o RDAP afirmar REGISTERED, não é reivindicável (delegação lame)."""
    reg = registrable_domain(name)
    if reg is None:
        return DomainCheck(None, Availability.REGISTERED)
    nx = await ns_nxdomain(reg)
    if nx is None:
        return DomainCheck(reg, Availability.UNKNOWN)
    if not nx:  # a zona existe
        if rdap is not None:
            av = await rdap(reg)
            if av == Availability.PENDING_RELEASE:
                return DomainCheck(reg, av)  # expira, mas o NS ainda responde
        return DomainCheck(reg, Availability.REGISTERED)
    # NS NXDOMAIN: fora da zona do TLD
    if rdap is None:
        return DomainCheck(reg, Availability.OUT_OF_ZONE)
    av = await rdap(reg)
    if av == Availability.UNKNOWN:
        return DomainCheck(reg, Availability.OUT_OF_ZONE)  # RDAP falhou: fica o sinal do DNS
    return DomainCheck(reg, av)


# ── cliente RDAP concreto (httpx), resiliente: qualquer falha vira UNKNOWN ─────
def make_rdap(*, timeout: float = 10.0, verify: bool = True,
              bootstrap_url: str = IANA_RDAP_BOOTSTRAP,
              transport: "httpx.BaseTransport | None" = None) -> Rdap:
    """Devolve um callable `rdap(domínio) -> Availability` que consulta o RDAP
    público do TLD (via bootstrap da IANA, cacheado em memória por processo).

    Abre uma conexão HTTPS curta por consulta — RDAP só dispara em domínio já
    suspeito (CNAME dangling, include de SPF órfão), então o volume é mínimo e
    não vale um client de longa duração. Verifica o certificado (default): são
    dados de registro, não o alvo. Nunca levanta: sem servidor RDAP, rede
    bloqueada ou resposta estranha -> UNKNOWN, e o chamador cai no sinal do DNS.
    `transport` é injetável (testes offline)."""
    cache: dict[str, object] = {}

    def _client() -> httpx.AsyncClient:
        if transport is not None:
            return httpx.AsyncClient(timeout=timeout, transport=transport)
        return httpx.AsyncClient(timeout=timeout, verify=verify)

    async def _services() -> list:
        if "services" not in cache:
            services: list = []
            try:
                async with _client() as c:
                    r = await c.get(bootstrap_url)
                if r.status_code == 200:
                    services = r.json().get("services", [])
            except Exception as exc:  # noqa: BLE001 — bootstrap é best-effort
                log.debug("rdap: bootstrap falhou: %s", type(exc).__name__)
            cache["services"] = services
        return cache["services"]  # type: ignore[return-value]

    async def rdap(domain: str) -> Availability:
        tld = domain.rsplit(".", 1)[-1]
        base = rdap_base_for(tld, await _services())
        if not base:
            return Availability.UNKNOWN
        try:
            async with _client() as c:
                r = await c.get(f"{base}domain/{domain}",
                                headers={"Accept": "application/rdap+json"})
            body = r.json() if r.status_code == 200 else None
        except Exception as exc:  # noqa: BLE001 — RDAP é best-effort
            log.debug("rdap: consulta de %s falhou: %s", domain, type(exc).__name__)
            return Availability.UNKNOWN
        return rdap_availability(r.status_code, body)

    return rdap
