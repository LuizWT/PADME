"""Connect-scan assíncrono de portas (TCP).

DESLIGADO por padrão (é a coleta mais "ativa" do Padmé). Faz apenas um
connect completo — sem SYN raw, sem flags exóticas — para registrar quais
portas estão abertas. Uma porta nova aberta é um dos alertas mais valiosos.

Use somente contra hosts que você está autorizado a testar.
"""

from __future__ import annotations

import asyncio

from ..models import Kind, Record


async def _check_port(host: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def collect_host(host: str, ports: list[int], timeout: float) -> list[Record]:
    tasks = [_check_port(host, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    return [
        Record(kind=Kind.PORT, key=f"{host}:{p}", value="open")
        for p, ok in zip(ports, results)
        if ok
    ]
