"""Política de rede: não sondar ativamente IPs privados/reservados sem escolha
consciente, e não seguir redirects por padrão (anti-SSRF).

A Padmé monitora superfície EXTERNA. Um host descoberto via CT/DNS pode resolver
para uma faixa interna (10/8, 192.168/16, 127/8, link-local, ULA IPv6...), e aí
HTTP/TLS/port-scan sairiam da máquina do operador contra a rede interna. Um
redirect `Location: http://127.0.0.1/` teria o mesmo efeito. Por padrão isso é
bloqueado; quem realmente quer monitorar rede interna liga `allow_private_ips`.

Com `follow_redirects` ligado, cada salto é seguido MANUALMENTE e validado aqui
(`redirect_target_allowed`) antes da requisição — um redirect para rede interna
não é seguido; o destino fica só registrado.

Limite honesto: a checagem resolve o nome ANTES da conexão, e a conexão resolve
de novo. Um servidor DNS hostil pode responder público na checagem e privado na
conexão (DNS rebinding). A trava reduz a superfície, não a elimina.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def is_public_ip(ip: str) -> bool:
    """True só para endereços globalmente roteáveis (`is_global`). Privado,
    loopback, link-local, reservado, CGNAT (100.64.0.0/10), multicast,
    unspecified, ULA IPv6… -> False. IPv4 embutido em IPv6 (mapeado ::ffff:,
    6to4 2002::/16, NAT64 64:ff9b::/96) é avaliado pelo IPv4 de dentro.
    Entrada inválida -> False (na dúvida, trata como não-público)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        inner = addr.ipv4_mapped or addr.sixtofour
        if inner is None and addr in _NAT64:
            inner = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        if inner is not None:
            addr = inner
    return addr.is_global and not addr.is_multicast


def any_disallowed(ips: set[str] | frozenset[str] | list[str]) -> bool:
    """True se ALGUM IP resolvido é privado/reservado. Usado como trava: se um
    host resolve para qualquer IP interno, não sondamos ativamente (defesa
    contra DNS rebinding também — basta um IP interno para bloquear)."""
    return any(not is_public_ip(ip) for ip in ips)


async def redirect_target_allowed(url: str, allow_private: bool,
                                  timeout: float = 5.0) -> bool:
    """Um salto de redirect pode ser seguido? Só http/https; com
    `allow_private` desligado, o destino precisa ser público — IP literal é
    checado direto, nome de host é RESOLVIDO e bloqueado se algum IP for
    privado/reservado (ou se não resolver: na dúvida, não segue)."""
    if url.split("://", 1)[0].lower() not in ("http", "https") or "://" not in url:
        return False
    if allow_private:
        return True
    host = _host_of(url)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return is_public_ip(host)
    except ValueError:
        pass
    ips = await _resolve_host(host, timeout)
    return bool(ips) and not any_disallowed(ips)


async def _resolve_host(host: str, timeout: float) -> set[str]:
    """IPs do host (A/AAAA via getaddrinfo). Falha/timeout -> vazio."""
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, proto=socket.IPPROTO_TCP),
            timeout=timeout)
    except Exception:  # noqa: BLE001 — não resolveu: não dá pra validar
        return set()
    return {info[4][0] for info in infos}


def _host_of(url: str) -> str:
    """Extrai o host de uma URL/Location de forma tolerante (sem depender de
    esquema). Remove credenciais e porta. Vazio se não der pra extrair."""
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):  # IPv6 literal [::1]:443
        return s[1: s.index("]")] if "]" in s else s[1:]
    return s.rsplit(":", 1)[0] if s.count(":") == 1 else s
