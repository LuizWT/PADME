"""Connect-scan assíncrono de portas (TCP) com banner-grab leve.

DESLIGADO por padrão (é a coleta mais "ativa" do Padmé). Faz um connect completo
e, se o serviço mandar um banner de saudação (SSH/SMTP/FTP…), lê os primeiros
bytes. O banner entra no valor da porta — então uma MUDANÇA de banner (ex.: versão
do OpenSSH mudou) vira um evento por si só, um sinal RED valioso.

Confiabilidade: porta recusada = definitivamente fechada; só-timeout = host
inalcançável -> `ok=False` (preserva). Banner-grab nunca derruba a checagem da
porta (falha de leitura = sem banner).

Use somente contra hosts que você está autorizado a testar.
"""

from __future__ import annotations

import asyncio

from ..models import CollectionResult, Kind, Record

_BANNER_BYTES = 128


def _clean_banner(data: bytes) -> str:
    """Primeira linha imprimível do banner, curta e sem lixo binário."""
    text = data.decode("latin-1", errors="ignore")
    line = text.splitlines()[0] if text.splitlines() else ""
    line = "".join(c for c in line if c.isprintable()).strip()
    return line[:80]


async def _check_port(host: str, port: int, timeout: float, grab: bool) -> tuple[str, str]:
    """Retorna (estado, banner). estado: 'open' | 'closed' | 'unknown'."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except ConnectionRefusedError:
        return "closed", ""
    except (asyncio.TimeoutError, TimeoutError):
        return "unknown", ""
    except OSError:
        return "unknown", ""
    banner = ""
    if grab:
        try:  # serviços tipo SSH/SMTP/FTP mandam saudação sozinhos
            data = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=min(timeout, 2.0))
            banner = _clean_banner(data)
        except Exception:  # noqa: BLE001 — sem banner não é erro
            banner = ""
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return "open", banner


async def collect_host(host: str, ports: list[int], timeout: float,
                       banner: bool = True) -> CollectionResult:
    results = await asyncio.gather(*(_check_port(host, p, timeout, banner) for p in ports))
    records = []
    for p, (state, ban) in zip(ports, results):
        if state != "open":
            continue
        value = f"open · {ban}" if ban else "open"
        records.append(Record(kind=Kind.PORT, key=f"{host}:{p}", value=value,
                              metadata={"port": p, "banner": ban} if ban else {"port": p}))
    ok = any(state in ("open", "closed") for state, _ in results)
    return CollectionResult(records=records, ok=ok)
