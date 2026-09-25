"""Resolução DNS passiva (A / AAAA / CNAME / MX) por host.

Usa dnspython se disponível (para CNAME/MX); caso contrário cai para
getaddrinfo (apenas A/AAAA). Um CNAME/registro novo costuma ser o primeiro
sinal de um serviço subindo ou de um takeover em potencial.
"""

from __future__ import annotations

import asyncio
import socket

from ..models import Kind, Record

try:
    import dns.asyncresolver  # type: ignore
    import dns.resolver  # type: ignore

    _HAS_DNSPYTHON = True
except Exception:  # pragma: no cover
    _HAS_DNSPYTHON = False


async def collect_host(host: str, timeout: float) -> list[Record]:
    if _HAS_DNSPYTHON:
        return await _collect_dnspython(host, timeout)
    return await _collect_getaddrinfo(host, timeout)


async def _collect_dnspython(host: str, timeout: float) -> list[Record]:
    records: list[Record] = []
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    for rtype in ("A", "AAAA", "CNAME", "MX"):
        try:
            answer = await resolver.resolve(host, rtype)
        except Exception:
            continue
        values = sorted(r.to_text().rstrip(".") for r in answer)
        for v in values:
            records.append(Record(kind=Kind.DNS, key=f"{host}|{rtype}|{v}", value=v))
    return records


async def _collect_getaddrinfo(host: str, timeout: float) -> list[Record]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=timeout
        )
    except Exception:
        return []
    ips = sorted({info[4][0] for info in infos})
    return [
        Record(kind=Kind.DNS, key=f"{host}|A|{ip}", value=ip) for ip in ips
    ]
