"""Fingerprint HTTP leve: um GET por host (http e https).

Registra status, header Server e o <title> da página. Mudança de status
(ex: 404 -> 200) ou de servidor costuma indicar um serviço novo ou alterado.
"""

from __future__ import annotations

import re

import httpx

from ..models import Kind, Record

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


async def collect_host(host: str, client: httpx.AsyncClient) -> list[Record]:
    records: list[Record] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = await client.get(url, follow_redirects=True)
        except Exception:
            continue
        server = r.headers.get("server", "")
        title = ""
        ctype = r.headers.get("content-type", "")
        if "text/html" in ctype:
            title = _title(r.text)
        value = f"{r.status_code} | {server} | {title}".strip()
        records.append(Record(kind=Kind.HTTP, key=url, value=value))
    return records
