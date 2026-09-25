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
    PORT = "port"
    HTTP = "http"
    TLS = "tls"
    TAKEOVER = "takeover"
    CERT_EXPIRY = "cert_expiry"


class EventType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


@dataclass(frozen=True)
class Record:
    kind: Kind
    key: str
    value: str = ""

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

    @property
    def is_noteworthy(self) -> bool:
        # Toda mudança é digna de nota; ponto único de ajuste caso queira
        # silenciar categorias no futuro.
        return True


@dataclass
class ScanResult:
    target: str
    records: list[Record] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
