"""Modelos de dados do Padmé.

A superfície de ataque de um alvo é representada como um conjunto de `Record`.
Cada Record é um fato observável e comparável:

    kind   -> categoria (subdomain, dns, port, http, tls)
    key    -> identidade estável do fato (fqdn, host:porta, url...)
    value  -> conteúdo que pode mudar sem mudar a identidade

Assim o diff vira uma simples operação de conjuntos:
    - key nova            -> ADDED
    - key sumiu           -> REMOVED
    - mesma key, value != -> CHANGED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Kind(str, Enum):
    SUBDOMAIN = "subdomain"
    DNS = "dns"
    NS = "ns"              # nameservers do apex (mudança = delegação / hijack de zona)
    MAILSEC = "mailsec"    # postura de e-mail no apex (SPF / DMARC)
    PORT = "port"
    HTTP = "http"
    HTTPSEC = "httpsec"    # postura de cabeçalhos de segurança do endpoint HTTP
    FAVICON = "favicon"    # hash do favicon (pivot de infraestrutura, estilo Shodan)
    TLS = "tls"
    TAKEOVER = "takeover"
    CERT_EXPIRY = "cert_expiry"
    WILDCARD = "wildcard"


# Escopo de observação: a "célula" dentro da qual a AUSÊNCIA de um Record
# significa REMOÇÃO real. Se o collector daquele escopo não observou com
# sucesso (ok=False), o estado anterior é preservado — um erro de coleta não
# pode virar "recurso removido" (ver storage.apply_scan / engine.observed_scopes).
#
# CERT_EXPIRY compartilha o escopo do TLS (mesmo collector/handshake): se o TLS
# foi observado, o cert também foi.
#
# HTTPSEC compartilha o escopo do HTTP: a postura de cabeçalhos vem da MESMA
# resposta do GET, então se o HTTP foi observado, os cabeçalhos também — e há
# sempre exatamente um HTTPSEC por host que respondeu (nunca falso REMOVED).
# FAVICON tem escopo PRÓPRIO (recurso /favicon.ico separado): 404 = ausência
# autoritativa (pode virar REMOVED real); timeout preserva (ver favicon.py).
_SCOPE_KIND = {
    Kind.CERT_EXPIRY: Kind.TLS,
    Kind.HTTPSEC: Kind.HTTP,
}

# Kinds cujo escopo é o alvo inteiro (não um host individual).
_TARGET_SCOPED = {Kind.SUBDOMAIN, Kind.WILDCARD, Kind.NS, Kind.MAILSEC}


def scope_of(kind: Kind, key: str, target: str) -> tuple[str, str]:
    """Escopo de observação de um Record: (kind_do_escopo, id_do_escopo).

    - subdomain/wildcard  -> ('subdomain'|'wildcard', target)   [alvo inteiro]
    - dns                 -> ('dns',  host)   host = key antes do primeiro '|'
    - http                -> ('http', host)   host = entre '://' e o primeiro '/'
    - tls / cert_expiry   -> ('tls',  host)   host = key sem ':porta'
    - port                -> ('port', host)
    - takeover            -> ('takeover', host)   key já é o host
    """
    scope_kind = _SCOPE_KIND.get(kind, kind)
    if kind in _TARGET_SCOPED:
        return (scope_kind.value, target)
    if kind == Kind.DNS:
        host = key.split("|", 1)[0]
    elif kind in (Kind.HTTP, Kind.HTTPSEC):  # key = URL (scheme://host)
        host = key.split("://", 1)[-1].split("/", 1)[0]
    elif kind in (Kind.TLS, Kind.CERT_EXPIRY, Kind.PORT):
        host = key.rsplit(":", 1)[0]
    else:  # takeover e quaisquer futuros host-scoped
        host = key
    return (scope_kind.value, host)


class EventType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


@dataclass(frozen=True)
class Record:
    kind: Kind
    key: str
    value: str = ""
    # metadados estruturados (issuer/expires/fp, status/server, service/reason…).
    # `value` continua sendo o resumo humano; metadata é pra automação (webhook/n8n),
    # painel e filtros. compare=False: não entra no ==/hash (o diff é por value).
    metadata: dict = field(default_factory=dict, compare=False)

    def ident(self) -> tuple[str, str]:
        return (self.kind.value, self.key)


@dataclass
class Event:
    target: str
    event_type: EventType
    kind: Kind
    key: str
    old_value: str | None = None
    new_value: str | None = None
    # metadados de rastreio (preenchidos ao persistir): úteis p/ dedup no n8n,
    # troubleshooting e o painel. `detected_at` é ISO-8601 em UTC.
    event_id: str | None = None
    scan_id: str | None = None
    detected_at: str | None = None
    metadata: dict = field(default_factory=dict)  # snapshot do metadata do Record

    @property
    def is_noteworthy(self) -> bool:
        # Toda mudança é digna de nota; ponto único de ajuste caso queira
        # silenciar categorias no futuro.
        return True


@dataclass
class CollectionResult:
    """Resultado de um collector para um escopo (um host, ou o alvo inteiro).

    `ok=True`  -> observação AUTORITATIVA: a ausência de um Record anterior
                  neste escopo pode ser tratada como remoção real.
    `ok=False` -> observação INCOMPLETA/desconhecida (timeout, erro de rede,
                  fonte indisponível): preserve o estado anterior; NÃO gere
                  REMOVED. É o coração de "erro de coleta != recurso removido".

    `hosts` carrega hosts extras a inspecionar (descoberta de subdomínio).
    """

    records: list[Record] = field(default_factory=list)
    ok: bool = True
    hosts: set[str] = field(default_factory=set)
    error: str | None = None


@dataclass
class ScanResult:
    target: str
    records: list[Record] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # escopos observados AUTORITATIVAMENTE neste scan: {(scope_kind, scope_id)}.
    # Só estes podem gerar REMOVED no diff; o resto é preservado.
    observed_scopes: set[tuple[str, str]] = field(default_factory=set)
