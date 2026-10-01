"""Pré-checagens de rede para o `padme doctor`.

A coleta depende de duas saídas que o firewall costuma tratar diferente do
tráfego comum: **TCP/53** (respostas DNS grandes — SPF com muitos includes,
DNSSEC — chegam truncadas por UDP e exigem TCP) e **HTTPS de saída** (RDAP, CT
logs, webhooks). Quando uma delas é bloqueada, a coleta não quebra: fica
INCONCLUSIVA e preserva o estado — o que some no meio do contador de
inconclusivos. Estas sondas tornam a causa explícita no diagnóstico.

Tudo é best-effort e não levanta: cada sonda devolve (ok, detalhe) e o doctor
só imprime. Nunca muda o código de saída (quem manda nele é a integridade do
banco)."""

from __future__ import annotations

import asyncio

try:
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


async def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    """True se dá para abrir um TCP para host:port dentro do timeout."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except Exception:
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True


def _system_resolvers() -> list[str]:
    """IPs dos resolvedores configurados no sistema (resolv.conf). Vazio se o
    dnspython não estiver disponível ou não houver nenhum."""
    if not _HAS_DNS:
        return []
    try:
        return list(dns.resolver.Resolver().nameservers)
    except Exception:
        return []


async def check_dns_tcp(timeout: float = 5.0) -> tuple[bool | None, str]:
    """TCP/53 chega ao primeiro resolvedor do sistema? (None = sem resolvedor
    conhecido p/ testar). Respostas DNS grandes caem para TCP; se ele é
    bloqueado, SPF de domínios grandes fica sempre inconclusivo."""
    resolvers = _system_resolvers()
    if not resolvers:
        return None, "nenhum resolvedor DNS configurado para testar"
    ip = resolvers[0]
    if await _tcp_connect(ip, 53, timeout):
        return True, f"TCP/53 para {ip} OK"
    return False, (f"TCP/53 para {ip} bloqueado — respostas DNS grandes (SPF com "
                   "muitos includes) ficarão inconclusivas")


async def check_https(host: str = "data.iana.org", timeout: float = 5.0) -> tuple[bool, str]:
    """HTTPS de saída chega a `host`:443? (RDAP usa o bootstrap da IANA; CT logs
    e webhooks também precisam de 443 de saída)."""
    if await _tcp_connect(host, 443, timeout):
        return True, f"HTTPS de saída para {host} OK"
    return False, (f"HTTPS de saída para {host} bloqueado — RDAP, CT logs e "
                   "webhooks podem falhar (coleta preserva o estado)")


async def run(cfg, timeout: float = 5.0) -> list[str]:
    """Roda as sondas pertinentes à config e devolve linhas de diagnóstico
    (prefixadas com 'ok:' ou '! ' para o doctor imprimir)."""
    lines: list[str] = []
    checks = [check_dns_tcp(timeout)]
    # HTTPS só é relevante se algo de saída está ligado (RDAP/CT/webhook)
    needs_https = (cfg.collectors.rdap or cfg.collectors.subdomains or cfg.webhook.enabled)
    if needs_https:
        checks.append(check_https(timeout=timeout))
    for ok, detail in await asyncio.gather(*checks):
        if ok is None:
            mark = "  — "   # não deu para testar (ex.: sem resolvedor)
        elif ok:
            mark = "  ok: "
        else:
            mark = "  ! "
        lines.append(f"{mark}{detail}")
    return lines
