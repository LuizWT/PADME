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
import re

from ..models import CollectionResult, Kind, Record

_BANNER_BYTES = 128

# serviço esperado por porta (determinístico, do número da porta — não do banner)
_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 465: "smtps", 587: "smtp",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    6379: "redis", 8080: "http", 8443: "https",
}

# produtos conhecidos que se anunciam no banner de saudação (lista curta e
# explicável — NÃO é um catálogo tipo Wappalyzer; cada match vem de um sinal claro).
_PRODUCTS = ("OpenSSH", "dropbear", "vsFTPd", "ProFTPD", "Pure-FTPd", "FileZilla",
             "Postfix", "Exim", "Sendmail", "Dovecot", "Courier", "nginx", "Apache")
_PRODUCT_RE = re.compile(
    r"\b(" + "|".join(re.escape(p) for p in _PRODUCTS) + r")\b[ /_]?v?(\d[\w.]*)?",
    re.IGNORECASE,
)
# SSH sempre abre com "SSH-<proto>-<software>"; extrai software_versão.
_SSH_RE = re.compile(r"SSH-\d+(?:\.\d+)?-([A-Za-z][\w.+-]*?)[_/ ]v?(\d[\w.+-]*)")
_SSH_RE_NAMEONLY = re.compile(r"SSH-\d+(?:\.\d+)?-(\S+)")


def _product_version(banner: str) -> tuple[str, str]:
    """(produto, versão) a partir do banner de saudação, ou ('','') se nada
    reconhecível. Cada regra corresponde a um protocolo que realmente se anuncia."""
    b = banner.strip()
    if not b:
        return "", ""
    m = _SSH_RE.match(b)
    if m:
        return m.group(1), m.group(2)
    m = _PRODUCT_RE.search(b)
    if m:
        return m.group(1), m.group(2) or ""
    m = _SSH_RE_NAMEONLY.match(b)
    if m:
        return m.group(1), ""
    return "", ""


def fingerprint(port: int, banner: str) -> dict:
    """Sinais de serviço/produto/versão de uma porta aberta. `service` vem do
    número da porta (determinístico); `product`/`version` do banner (quando o
    serviço se anuncia). Só inclui o que foi observado."""
    out: dict = {}
    svc = _PORT_SERVICE.get(port)
    if svc:
        out["service"] = svc
    product, version = _product_version(banner or "")
    if product:
        out["product"] = product
    if version:
        out["version"] = version
    return out


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
        md = {"port": p}
        if ban:
            md["banner"] = ban
        md.update(fingerprint(p, ban))  # service (da porta) + product/version (do banner)
        records.append(Record(kind=Kind.PORT, key=f"{host}:{p}", value=value, metadata=md))
    ok = any(state in ("open", "closed") for state, _ in results)
    return CollectionResult(records=records, ok=ok)
