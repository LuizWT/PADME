"""Tipos de alvo: domínio, IP único ou faixa (CIDR).

Um alvo IP ou faixa não tem DNS de domínio, subdomínios nem política de
e-mail: para ele rodam só os coletores que fazem sentido sem domínio (portas,
HTTP, TLS, DNS reverso). A faixa tem teto de hosts (`collectors.
max_hosts_per_target`) para não virar varredura de rede inteira, e os nomes
descobertos num IP (PTR, SANs do certificado) são registrados, nunca varridos.

A forma canônica é a chave do alvo no banco: `203.0.113.7`, `203.0.113.0/28`,
`2001:db8::1`, `2001:db8::/120`.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

TargetKind = Literal["domain", "ip", "net"]

DEFAULT_MAX_HOSTS = 256
_V4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_CIDR = re.compile(r"^[0-9a-f:.]+/\d{1,3}$")


def parse(raw: object) -> str | None:
    """Forma canônica de um IP ou de uma faixa; None se `raw` não parece IP
    (é domínio, e quem chama segue com a validação de domínio).

    Aceita IP com esquema, caminho ou porta (`https://203.0.113.7:8443/x`,
    `[2001:db8::1]:443`). Faixa com bits de host (`10.0.0.5/24`) é recusada com
    a forma certa na mensagem, em vez de corrigida calada."""
    t = str(raw).strip().lower()
    if _CIDR.match(t):
        try:
            net = ipaddress.ip_network(t, strict=True)
        except ValueError:
            try:
                certo = ipaddress.ip_network(t, strict=False)
            except ValueError:
                raise ValueError(f"faixa inválida: {raw!r}") from None
            raise ValueError(f"a faixa {raw!r} tem bits de host; use {certo}") from None
        if net.num_addresses == 1:   # /32 e /128 são um IP só
            return str(net.network_address)
        return str(net)
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):            # [2001:db8::1] ou [2001:db8::1]:443
        t = t[1:].split("]", 1)[0]
    elif t.count(":") == 1:          # 203.0.113.7:443
        t = t.rsplit(":", 1)[0]
    if _V4.match(t) or ":" in t:     # domínio nunca tem ':' depois de tirar a porta
        try:
            return str(ipaddress.ip_address(t))
        except ValueError:
            raise ValueError(f"IP inválido: {raw!r}") from None
    return None


def kind_of(target: str) -> TargetKind:
    if "/" in target:
        return "net"
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return "domain"
    return "ip"


def is_ip_target(target: str) -> bool:
    return kind_of(target) != "domain"


def host_count(target: str) -> int:
    """Quantos hosts o alvo tem (domínio = 1). Faixa grande não é expandida
    para contar."""
    if kind_of(target) != "net":
        return 1
    net = ipaddress.ip_network(target)
    if net.num_addresses > 1 << 20:
        return net.num_addresses
    return sum(1 for _ in net.hosts())


def hosts_of(target: str) -> list[str]:
    """Os IPs a sondar. Uma faixa vira os seus hosts (sem endereço de rede e de
    broadcast no IPv4); quem chama já validou o teto."""
    kind = kind_of(target)
    if kind == "domain":
        return [target]
    if kind == "ip":
        return [target]
    return [str(h) for h in ipaddress.ip_network(target).hosts()]


def url_host(host: str) -> str:
    """Host pronto para URL: IPv6 vai entre colchetes (`https://[2001:db8::1]`)."""
    return f"[{host}]" if ":" in host else host
