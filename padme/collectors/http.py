"""Fingerprint HTTP leve: um GET por host (http e https).

Registra status, header Server e o <title> da página. Mudança de status
(ex: 404 -> 200) ou de servidor costuma indicar um serviço novo ou alterado.

Segurança (anti-SSRF): NÃO segue redirects por padrão — um `Location:
http://127.0.0.1/` transformaria o monitor em proxy pra rede interna. Quando
não segue, registra o destino do redirect.

Memória: lê no máximo `max_bytes` do corpo (streaming) — não baixa uma página
de 100 MB só pra extrair um `<title>`. O corpo (truncado) é reaproveitado pelo
collector de takeover.

Confiabilidade: se nenhum dos esquemes respondeu (timeout/erro de conexão), o
resultado é `ok=False` — o estado HTTP anterior do host é preservado em vez de
virar "removido".
"""

from __future__ import annotations

import re

import httpx

from ..models import CollectionResult, Kind, Record

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
DEFAULT_MAX_BYTES = 262144  # 256 KiB — suficiente p/ <title> e fingerprints


def _title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


async def _fetch_limited(
    client: httpx.AsyncClient, url: str, follow_redirects: bool, max_bytes: int
) -> tuple[httpx.Response, str]:
    """GET com corpo limitado a `max_bytes`. Não lê corpo de redirect (3xx)."""
    async with client.stream("GET", url, follow_redirects=follow_redirects) as r:
        if 300 <= r.status_code < 400:
            return r, ""  # redirect: interessa o Location, não o corpo
        total = 0
        chunks: list[bytes] = []
        async for chunk in r.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        return r, b"".join(chunks)[:max_bytes].decode("utf-8", errors="ignore")


async def collect_host(
    host: str,
    client: httpx.AsyncClient,
    cache: dict[str, str] | None = None,
    follow_redirects: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> CollectionResult:
    records: list[Record] = []
    observed_any = False
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r, body = await _fetch_limited(client, url, follow_redirects, max_bytes)
        except Exception:
            continue  # esse esquema não respondeu; tenta o outro
        observed_any = True
        if cache is not None:  # reaproveitado pelo collector de takeover
            cache[url] = body
        server = r.headers.get("server", "")
        location = r.headers.get("location", "") if 300 <= r.status_code < 400 else ""
        title = ""
        detail = ""
        if location:
            detail = f"→ {location}"  # não seguimos: registramos o destino
        elif "text/html" in r.headers.get("content-type", ""):
            title = _title(body)
            detail = title
        value = f"{r.status_code} | {server} | {detail}".strip()
        records.append(Record(kind=Kind.HTTP, key=url, value=value, metadata={
            "status": r.status_code, "server": server, "title": title,
            "location": location or None, "scheme": scheme,
        }))
    return CollectionResult(records=records, ok=observed_any)
