"""Enumeração passiva de subdomínios via Certificate Transparency.

Fontes suportadas (tenta em ordem; a primeira que responder vale, e as demais
enriquecem o resultado):
  1. crt.name  -> https://crt.name/v1/search?apex=DOMAIN
  2. crt.sh     -> https://crt.sh/?q=%25.DOMAIN&output=json

Como o schema exato do crt.name pode variar, o parser é DEFENSIVO: ele varre
a estrutura JSON inteira e coleta qualquer string que pareça um hostname sob o
apex. Assim funciona independente do formato exato da resposta.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

import httpx

from ..models import CollectionResult, Kind, Record

log = logging.getLogger("padme")

# hostname válido (labels alfanuméricos + hífen, com wildcard opcional no início)
_HOST_RE = re.compile(
    r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.IGNORECASE
)


def _iter_strings(node: Any) -> Iterable[str]:
    """Percorre recursivamente qualquer JSON e devolve todas as strings."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _iter_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_strings(v)


def _extract_hosts(payload: Any, apex: str) -> set[str]:
    apex = apex.lower().lstrip(".")
    found: set[str] = set()
    for raw in _iter_strings(payload):
        for chunk in re.split(r"[\s,;]+", raw):
            for m in _HOST_RE.findall(chunk):
                host = m.lower().lstrip("*.").strip(".")
                if host == apex or host.endswith("." + apex):
                    found.add(host)
    return found


async def _fetch_json(client: httpx.AsyncClient, url: str) -> tuple[Any | None, bool]:
    """Retorna (payload, respondeu_ok). respondeu_ok=False em erro/timeout/HTTP
    != 2xx — usado para distinguir 'fonte vazia' de 'fonte indisponível'."""
    try:
        r = await client.get(url)
        r.raise_for_status()
        return r.json(), True
    except Exception as exc:  # noqa: BLE001
        log.debug("subdomains: fonte falhou %s (%s)", url, type(exc).__name__)
        return None, False


async def collect(target: str, client: httpx.AsyncClient) -> CollectionResult:
    """Descobre subdomínios via CT logs.

    `ok=True` só quando ALGUMA fonte respondeu — se todas as fontes caírem, o
    escopo de subdomínio fica não-observado e o estado anterior é preservado
    (não apagamos todos os subdomínios por causa de uma indisponibilidade do
    crt.sh/crt.name).
    """
    apex = target.lower().lstrip(".")
    hosts: set[str] = {apex}

    sources = [
        f"https://crt.name/v1/search?apex={apex}",
        f"https://crt.sh/?q=%25.{apex}&output=json",
    ]
    any_source_ok = False
    for url in sources:
        payload, source_ok = await _fetch_json(client, url)
        any_source_ok = any_source_ok or source_ok
        if payload is not None:
            hosts |= _extract_hosts(payload, apex)

    # O apex é host de INSPEÇÃO, mas não é um "subdomínio": não vira Record
    # SUBDOMAIN (senão o próprio alvo apareceria como subdomínio de si mesmo).
    records = [Record(kind=Kind.SUBDOMAIN, key=h) for h in sorted(hosts) if h != apex]
    return CollectionResult(records=records, ok=any_source_ok, hosts=hosts)
