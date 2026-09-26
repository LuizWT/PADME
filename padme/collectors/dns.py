"""Resolução DNS passiva (A / AAAA / CNAME / MX) por host.

Usa dnspython se disponível (para CNAME/MX); caso contrário cai para
getaddrinfo (apenas A/AAAA). Um CNAME/registro novo costuma ser o primeiro
sinal de um serviço subindo ou de um takeover em potencial.

Confiabilidade: distingue resposta DEFINITIVA (respondeu, ou NXDOMAIN/NoAnswer)
de FALHA TRANSITÓRIA (timeout, SERVFAIL). Timeout em qualquer consulta marca o
resultado como `ok=False` — o estado DNS anterior do host é preservado em vez de
virar "removido" por causa de uma falha de rede.
"""

from __future__ import annotations

import asyncio
import socket

from ..models import CollectionResult, Kind, Record

try:
    import dns.asyncresolver  # type: ignore
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore

    _HAS_DNSPYTHON = True
    # Exceções DEFINITIVAS: o servidor respondeu que não há esse registro.
    _DEFINITIVE = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)
except Exception:  # pragma: no cover
    _HAS_DNSPYTHON = False
    _DEFINITIVE = ()


async def collect_host(host: str, timeout: float) -> CollectionResult:
    if _HAS_DNSPYTHON:
        return await _collect_dnspython(host, timeout)
    return await _collect_getaddrinfo(host, timeout)


async def _collect_dnspython(host: str, timeout: float) -> CollectionResult:
    records: list[Record] = []
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    ok = True  # vira False se qualquer consulta for inconclusiva (transitória)
    for rtype in ("A", "AAAA", "CNAME", "MX"):
        try:
            answer = await resolver.resolve(host, rtype)
        except _DEFINITIVE:
            continue  # resposta definitiva: não há esse registro (não é falha)
        except Exception:
            ok = False  # timeout / SERVFAIL / resolver quebrou -> desconhecido
            continue
        values = sorted(r.to_text().rstrip(".") for r in answer)
        for v in values:
            records.append(Record(kind=Kind.DNS, key=f"{host}|{rtype}|{v}", value=v))
    return CollectionResult(records=records, ok=ok)


async def _collect_getaddrinfo(host: str, timeout: float) -> CollectionResult:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=timeout
        )
    except socket.gaierror as exc:
        # EAI_NONAME / EAI_NODATA: host definitivamente sem endereço (ok, vazio).
        # Outros gaierror: tratado como transitório (na dúvida, preserva).
        definitive = exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME))
        return CollectionResult(records=[], ok=definitive)
    except Exception:
        return CollectionResult(records=[], ok=False)  # timeout etc.
    ips = sorted({info[4][0] for info in infos})
    return CollectionResult(
        records=[Record(kind=Kind.DNS, key=f"{host}|A|{ip}", value=ip) for ip in ips],
        ok=True,
    )
