"""Fingerprint HTTP leve: um GET por host (http e https).

Registra status, header Server e o <title> da página. Mudança de status
(ex: 404 -> 200) ou de servidor costuma indicar um serviço novo ou alterado.

Segurança (anti-SSRF): NÃO segue redirects por padrão — um `Location:
http://127.0.0.1/` transformaria o monitor em proxy pra rede interna. Quando
não segue, registra o destino do redirect para você ver a cadeia.

Confiabilidade: se nenhum dos esquemes respondeu (timeout/erro de conexão), o
resultado é `ok=False` — o estado HTTP anterior do host é preservado em vez de
virar "removido".
"""

from __future__ import annotations

import re

import httpx

from ..models import CollectionResult, Kind, Record

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


async def collect_host(
    host: str,
    client: httpx.AsyncClient,
    cache: dict[str, str] | None = None,
    follow_redirects: bool = False,
) -> CollectionResult:
    records: list[Record] = []
    observed_any = False
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = await client.get(url, follow_redirects=follow_redirects)
        except Exception:
            continue  # esse esquema não respondeu; tenta o outro
        observed_any = True
        if cache is not None:  # reaproveitado pelo collector de takeover
            cache[url] = r.text
        server = r.headers.get("server", "")
        detail = ""
        if 300 <= r.status_code < 400 and "location" in r.headers:
            detail = f"→ {r.headers['location']}"  # não seguimos: registramos o destino
        else:
            ctype = r.headers.get("content-type", "")
            if "text/html" in ctype:
                detail = _title(r.text)
        value = f"{r.status_code} | {server} | {detail}".strip()
        records.append(Record(kind=Kind.HTTP, key=url, value=value))
    return CollectionResult(records=records, ok=observed_any)
