"""Conhecimento de portas em UM lugar: que serviço a porta convencionalmente
carrega e quais são de risco quando aparecem abertas na borda.

Antes eram dois mapas que não se conversavam (o fingerprint do collector de
portas e a lista de portas perigosas do motor de risco). Agora o collector
nomeia o serviço e o risco classifica pela MESMA tabela.
"""

from __future__ import annotations

# serviço convencional/IANA por porta (determinístico — não vem do banner)
SERVICE_BY_PORT: dict[int, str] = {
    # básico / correio / web
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    69: "tftp", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s", 990: "ftps",
    8080: "http", 8000: "http", 8081: "http", 8443: "https", 8888: "http",
    # infra / rede / diretório
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 161: "snmp", 389: "ldap", 445: "smb", 636: "ldaps",
    873: "rsync", 1080: "socks", 2049: "nfs", 3128: "http-proxy",
    5060: "sip",
    # bancos de dados
    1433: "mssql", 1521: "oracle", 3306: "mysql", 5432: "postgresql",
    5984: "couchdb", 6379: "redis", 9042: "cassandra", 11211: "memcached",
    27017: "mongodb",
    # orquestração / mensageria / observabilidade / big data
    2375: "docker", 2376: "docker-tls", 2181: "zookeeper", 5601: "kibana",
    6443: "kubernetes-api", 8086: "influxdb", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 15672: "rabbitmq",
    # acesso remoto / shell
    512: "rexec", 513: "rlogin", 514: "rsh", 3389: "rdp", 4444: "shell",
    5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
}

# Acesso administrativo remoto sem autenticação forte: recém-aberta = crítico.
REMOTE_ACCESS_PORTS: frozenset[int] = frozenset({
    23, 445, 512, 513, 514, 2375, 2376, 3389, 4444, 5900, 5985, 5986,
})
# Serviços de dados que costumam ficar expostos sem auth: recém-aberta = crítico.
DATA_PORTS: frozenset[int] = frozenset({
    1433, 2049, 3306, 5432, 5984, 6379, 9200, 11211, 27017,
})
HIGH_RISK_PORTS: frozenset[int] = REMOTE_ACCESS_PORTS | DATA_PORTS

# TLS implícito (handshake logo na conexão). STARTTLS (25/587/143…) fica de fora:
# o handshake direto falharia e viraria coleta inconclusiva.
IMPLICIT_TLS_PORTS: frozenset[int] = frozenset({
    443, 465, 636, 853, 990, 993, 995, 2376, 5986, 6443, 8443, 9443,
})
