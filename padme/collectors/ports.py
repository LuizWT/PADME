"""Connect-scan assíncrono de portas (TCP) com banner-grab leve.

DESLIGADO por padrão (é a coleta mais "ativa" do Padmé). Faz um connect completo
e, se o serviço mandar um banner de saudação (SSH/SMTP/FTP…), lê os primeiros
bytes. O banner entra no valor da porta — então uma MUDANÇA de banner (ex.: versão
do OpenSSH mudou) vira um evento por si só, um sinal RED valioso.

A maioria dos serviços de saudação é texto livre (SSH/SMTP/FTP/POP3/IMAP): o
produto/versão sai por regra de protocolo (SSH) ou por uma allowlist curta de
nomes que realmente se anunciam. Alguns protocolos falam PRIMEIRO com um
greeting BINÁRIO e ESTRUTURADO — é o caso do MySQL/MariaDB, cujo handshake
carrega a versão do servidor em posição fixa (sinal claro, decodificável sem
adivinhação); esse é decodificado para um banner legível ("MySQL 8.0.34") já na
leitura, e o fingerprint de texto extrai produto/versão dali.

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

# serviço esperado por porta (determinístico, do número da porta — não do banner).
# Foco em monitoração de exposição: além do básico, portas que, abertas na
# borda, são sinal por si só (bancos, admin, orquestração, cache, mensageria).
# Cada entrada é a atribuição convencional/IANA da porta — não um chute.
_PORT_SERVICE = {
    # básico / correio / web
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 990: "ftps",
    8080: "http", 8000: "http", 8081: "http", 8443: "https", 8888: "http",
    # infra / rede / diretório
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 161: "snmp", 389: "ldap", 445: "smb", 636: "ldaps",
    873: "rsync", 1080: "socks", 2049: "nfs", 3128: "http-proxy",
    5060: "sip", 5900: "vnc",
    # bancos de dados
    1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgresql",
    5984: "couchdb", 6379: "redis", 9042: "cassandra", 11211: "memcached",
    27017: "mongodb",
    # orquestração / mensageria / observabilidade / big data
    2375: "docker", 2376: "docker-tls", 2181: "zookeeper", 5601: "kibana",
    6443: "kubernetes-api", 8086: "influxdb", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 15672: "rabbitmq",
    # acesso remoto
    3389: "rdp",
}

# produtos conhecidos que se anunciam no banner de SAUDAÇÃO (o serviço fala
# primeiro, sem requisição). Lista curta e explicável — NÃO é um catálogo tipo
# Wappalyzer; cada match vem de um sinal claro. Servidores HTTP não saúdam num
# connect puro, então nginx/Apache raramente casam aqui (ficam pela porta).
_PRODUCTS = ("OpenSSH", "dropbear", "libssh",
             "vsFTPd", "ProFTPD", "Pure-FTPd", "FileZilla", "Serv-U",
             "CrushFTP", "bftpd", "Microsoft FTP Service",
             "Postfix", "Exim", "Sendmail", "OpenSMTPD", "Haraka",
             "Microsoft ESMTP", "Zimbra", "MailEnable",
             "Dovecot", "Courier", "Cyrus",
             "MariaDB", "MySQL",
             "nginx", "Apache")
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


def _mysql_banner(data: bytes) -> str:
    """Versão do servidor a partir do handshake inicial do MySQL/MariaDB, que
    fala PRIMEIRO. Layout (protocolo 10): [3B tamanho][1B seq=0][1B 0x0a]
    [versão terminada em NUL]. Só reconhece quando a assinatura casa E a versão
    tem forma de versão — sinal claro, sem adivinhação. Devolve '' se não for.

    MariaDB anuncia com um prefixo de replicação falso '5.5.5-' seguido da versão
    real e do sufixo '-MariaDB'; extraímos a versão real."""
    if len(data) >= 6 and data[3] == 0x00 and data[4] == 0x0A:
        end = data.find(b"\x00", 5)
        raw = data[5:(end if end != -1 else len(data))].decode("latin-1", "ignore")
        ver = "".join(c for c in raw if c.isprintable()).strip()
        if "mariadb" in ver.lower():
            m = re.search(r"(\d+\.\d+\.\d+)-MariaDB", ver, re.IGNORECASE)
            return f"MariaDB {m.group(1)}" if m else "MariaDB"
        m = re.match(r"\d+\.\d+(?:\.\d+)?", ver)
        if m:
            return f"MySQL {m.group(0)}"
    return ""


def _decode_banner(data: bytes) -> str:
    """Banner legível: decodifica protocolos binários estruturados (MySQL/
    MariaDB) e cai na primeira linha de texto para o resto."""
    return _mysql_banner(data) or _clean_banner(data)


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
            banner = _decode_banner(data)
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
