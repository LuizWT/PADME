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

import re
from typing import Any, Iterable

import httpx

from ..models import Kind, Record

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


async def _fetch_json(client: httpx.AsyncClient, url: str) -> Any | None:
    try:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


async def collect(target: str, client: httpx.AsyncClient) -> tuple[list[Record], set[str]]:
    """Retorna (records de subdomínio, conjunto de hosts para os host-collectors)."""
    apex = target.lower().lstrip(".")
    hosts: set[str] = {apex}

    sources = [
        f"https://crt.name/v1/search?apex={apex}",
        f"https://crt.sh/?q=%25.{apex}&output=json",
    ]
    for url in sources:
        payload = await _fetch_json(client, url)
        if payload is not None:
            hosts |= _extract_hosts(payload, apex)

    records = [Record(kind=Kind.SUBDOMAIN, key=h) for h in sorted(hosts)]
    return records, hosts
