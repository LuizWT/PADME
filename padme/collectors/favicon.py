"""Hash do favicon — pivot de infraestrutura (estilo Shodan).

Dois hosts que servem o MESMO favicon costumam pertencer à mesma stack/infra.
Ferramentas como o Shodan usam o `mmh3` (murmurhash3) do favicon em base64 para
esse pivot. Aqui o objetivo é INTERNO — comparar hosts observados PELO Padmé
entre si — então usamos `sha256` da stdlib (truncado) em vez de arrastar a
dependência `mmh3`: o número não precisa bater com o do Shodan, só ser estável e
comparável. Se um dia você quiser cruzar com o Shodan, dá pra trocar o algoritmo
sem mudar o resto.

Ativo LEVE: é UM GET extra a `/favicon.ico` (não é passivo — depende de uma
requisição). O engine só chama isto quando o host já respondeu HTTP, pra não
sondar host morto. Confiabilidade: o servidor respondeu (mesmo 404) = ausência
AUTORITATIVA (pode virar REMOVED real); timeout/erro de conexão = `ok=False`
(preserva o achado anterior).
"""

from __future__ import annotations

import hashlib

import httpx

from ..models import CollectionResult, Kind, Record
from .http import open_stream

# favicons são pequenos; teto próprio pra não baixar um "favicon" de 50 MB.
FAVICON_MAX_BYTES = 1_048_576  # 1 MiB


async def _fetch_bytes(
    client: httpx.AsyncClient, url: str, follow_redirects: bool, max_bytes: int,
    allow_private: bool = False,
) -> tuple[int, bytes]:
    """GET dos BYTES crus (não decodifica — o hash precisa do binário), limitado
    a `max_bytes`. Não lê corpo de redirect. Redirects validados (open_stream)."""
    async with open_stream(client, url, follow_redirects, allow_private) as r:
        if 300 <= r.status_code < 400:
            return r.status_code, b""
        total = 0
        chunks: list[bytes] = []
        async for chunk in r.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        return r.status_code, b"".join(chunks)[:max_bytes]


async def collect_host(
    host: str,
    client: httpx.AsyncClient,
    follow_redirects: bool = False,
    max_bytes: int = FAVICON_MAX_BYTES,
    allow_private: bool = False,
) -> CollectionResult:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/favicon.ico"
        try:
            status, data = await _fetch_bytes(client, url, follow_redirects, max_bytes,
                                              allow_private)
        except Exception:
            continue  # esse esquema não respondeu; tenta o outro
        if status == 200 and data:
            digest = hashlib.sha256(data).hexdigest()[:16]
            return CollectionResult(records=[Record(
                kind=Kind.FAVICON, key=host, value=digest,
                metadata={"algo": "sha256/16", "url": url,
                          "bytes": len(data), "status": status},
            )], ok=True)
        # respondeu, mas sem favicon utilizável (404/403/vazio) -> ausência
        # autoritativa: sem record, ok=True (permite REMOVED real se havia um).
        return CollectionResult(records=[], ok=True)
    # nenhum esquema respondeu (timeout/erro) -> inconclusivo, preserva
    return CollectionResult(records=[], ok=False)
