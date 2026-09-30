"""Resolução DNS passiva (A / AAAA / CNAME / MX) por host.

Usa dnspython se disponível (para CNAME/MX); caso contrário cai para
getaddrinfo (apenas A/AAAA). Um CNAME/registro novo costuma ser o primeiro
sinal de um serviço subindo ou de um takeover em potencial.

Um Record por (host, tipo): key `host|TIPO`, valor = o CONJUNTO de respostas
ordenado ("1.1.1.1, 2.2.2.2"), lista em `metadata.values`. Assim a rotação de IP
de uma CDN vira UM `CHANGED` (com o diff do conjunto), e não um par
ADDED+REMOVED por IP a cada ciclo — que era ruído e distorcia a tendência.

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
        values = sorted({r.to_text().rstrip(".") for r in answer})
        if values:
            records.append(dns_record(host, rtype, values))
    return CollectionResult(records=records, ok=ok)


def dns_record(host: str, rtype: str, values: list[str]) -> Record:
    """Record agregado de um (host, tipo)."""
    vals = sorted(set(values))
    return Record(kind=Kind.DNS, key=f"{host}|{rtype}", value=", ".join(vals),
                  metadata={"values": vals})


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
    ips = {info[4][0] for info in infos}
    v4 = [ip for ip in ips if ":" not in ip]
    v6 = [ip for ip in ips if ":" in ip]
    records = [dns_record(host, t, vals) for t, vals in (("A", v4), ("AAAA", v6)) if vals]
    return CollectionResult(records=records, ok=True)
