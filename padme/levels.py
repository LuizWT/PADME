"""Níveis de notificação (estilo log level) para o retorno via Telegram.

O terminal sempre mostra tudo. O nível define o LIMIAR mínimo de severidade
que é enviado ao Telegram — do mais barulhento ao mais crítico:

    DEBUG    (0)  tudo, inclusive registros DNS
    LOW      (1)  remoções e mudanças menores
    MEDIUM   (2)  HTTP/TLS mudou, serviço novo   <- padrão
    HIGH     (3)  porta nova aberta / subdomínio novo (superfície cresceu)
    CRITICAL (4)  só subdomain takeover

Severidade de cada evento (kind + tipo):
    takeover                  -> CRITICAL
    port/subdomain ADDED      -> HIGH
    http/tls (add/changed)    -> MEDIUM
    http/tls REMOVED,
      port/subdomain removido -> LOW
    dns                       -> DEBUG
"""

from __future__ import annotations

from enum import IntEnum

from .models import Event, EventType, Kind


class Level(IntEnum):
    DEBUG = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


_ALIASES = {
    "all": Level.DEBUG,
    "verbose": Level.DEBUG,
    "info": Level.LOW,
}


def parse_level(value: object, default: Level = Level.MEDIUM) -> Level:
    """Aceita nome ('high'), número ('3') ou Level; cai no default se inválido."""
    if isinstance(value, Level):
        return value
    s = str(value).strip().lower()
    if s in _ALIASES:
        return _ALIASES[s]
    for lv in Level:
        if s == lv.name.lower() or s == str(lv.value):
            return lv
    return default


def severity(e: Event) -> Level:
    k, t = e.kind, e.event_type
    if k == Kind.TAKEOVER:
        return Level.CRITICAL
    if k == Kind.CERT_EXPIRY:
        return Level.HIGH
    if t == EventType.ADDED and k in (Kind.PORT, Kind.SUBDOMAIN):
        return Level.HIGH
    if k in (Kind.HTTP, Kind.TLS):
        return Level.LOW if t == EventType.REMOVED else Level.MEDIUM
    if k in (Kind.PORT, Kind.SUBDOMAIN):  # removido ou alterado
        return Level.LOW
    return Level.DEBUG  # dns


def filter_events(events: list[Event], level: Level) -> list[Event]:
    """Mantém só os eventos com severidade >= level."""
    return [e for e in events if severity(e) >= level]
