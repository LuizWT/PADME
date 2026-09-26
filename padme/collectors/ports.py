"""Connect-scan assíncrono de portas (TCP).

DESLIGADO por padrão (é a coleta mais "ativa" do Padmé). Faz apenas um
connect completo — sem SYN raw, sem flags exóticas — para registrar quais
portas estão abertas. Uma porta nova aberta é um dos alertas mais valiosos.

Confiabilidade: distingue porta fechada (recusada -> definitivo) de host
inalcançável (todas as portas em timeout -> desconhecido). Se NENHUMA porta deu
resposta definitiva, o resultado é `ok=False` e as portas antes abertas são
preservadas em vez de reportadas como fechadas.

Use somente contra hosts que você está autorizado a testar.
"""

from __future__ import annotations

import asyncio

from ..models import CollectionResult, Kind, Record


async def _check_port(host: str, port: int, timeout: float) -> str:
    """Retorna 'open' | 'closed' | 'unknown'."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return "open"
    except ConnectionRefusedError:
        return "closed"  # definitivo: nada escutando nessa porta
    except (asyncio.TimeoutError, TimeoutError):
        return "unknown"  # filtrado ou host fora do ar
    except OSError:
        return "unknown"


async def collect_host(host: str, ports: list[int], timeout: float) -> CollectionResult:
    results = await asyncio.gather(*(_check_port(host, p, timeout) for p in ports))
    records = [
        Record(kind=Kind.PORT, key=f"{host}:{p}", value="open")
        for p, state in zip(ports, results)
        if state == "open"
    ]
    # observação autoritativa se alguma porta deu resposta definitiva
    # (aberta ou recusada); só timeouts -> host inalcançável -> preserva.
    ok = any(state in ("open", "closed") for state in results)
    return CollectionResult(records=records, ok=ok)
