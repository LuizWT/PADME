"""Política de rede: não sondar ativamente IPs privados/reservados sem escolha
consciente, e não seguir redirects por padrão (anti-SSRF).

A Padmé monitora superfície EXTERNA. Um host descoberto via CT/DNS pode resolver
para uma faixa interna (10/8, 192.168/16, 127/8, link-local, ULA IPv6...), e aí
HTTP/TLS/port-scan sairiam da máquina do operador contra a rede interna. Um
redirect `Location: http://127.0.0.1/` teria o mesmo efeito. Por padrão isso é
bloqueado; quem realmente quer monitorar rede interna liga `allow_private_ips`.
"""

from __future__ import annotations

import ipaddress


def is_public_ip(ip: str) -> bool:
    """True só para endereços globalmente roteáveis. Qualquer coisa privada,
    loopback, link-local, reservada, multicast, unspecified ou ULA IPv6 -> False.
    Entrada inválida -> False (na dúvida, trata como não-público)."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def any_disallowed(ips: set[str] | frozenset[str] | list[str]) -> bool:
    """True se ALGUM IP resolvido é privado/reservado. Usado como trava: se um
    host resolve para qualquer IP interno, não sondamos ativamente (defesa
    contra DNS rebinding também — basta um IP interno para bloquear)."""
    return any(not is_public_ip(ip) for ip in ips)


def redirect_allowed(location: str, allow_private: bool) -> bool:
    """Um destino de redirect só é elegível a ser seguido se o host de destino
    for um IP público literal (ou se allow_private estiver ligado). Nome de host
    (não-IP) não é validável aqui sem resolver -> não seguimos por padrão."""
    if allow_private:
        return True
    host = _host_of(location)
    if not host:
        return False
    return is_public_ip(host)


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
