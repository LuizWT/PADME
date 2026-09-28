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
    cert_expiry / wildcard    -> HIGH
    port/subdomain ADDED      -> HIGH
    http/tls (add/changed)    -> MEDIUM
    http/tls REMOVED,
      port/subdomain removido -> LOW
    dns                       -> DEBUG
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .models import Event, EventType, Kind


class Level(IntEnum):
    DEBUG = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Portas de acesso administrativo remoto / serviços de dados que costumam ficar
# sem autenticação forte. Uma porta DESTAS recém-aberta é bem mais grave que uma
# porta comum nova — daí a elevação contextual (item: priorização de risco).
_HIGH_RISK_PORTS: dict[int, str] = {
    23: "Telnet", 445: "SMB", 512: "rexec", 513: "rlogin", 514: "rsh",
    1433: "MSSQL", 2049: "NFS", 2375: "Docker API", 2376: "Docker API",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 5985: "WinRM", 5986: "WinRM",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}


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


def _base_severity(e: Event) -> Level:
    """Severidade BASE por (categoria, tipo) — a régua histórica, estável."""
    k, t = e.kind, e.event_type
    if k == Kind.TAKEOVER:
        return Level.CRITICAL
    if k in (Kind.CERT_EXPIRY, Kind.WILDCARD):
        return Level.HIGH
    if k == Kind.NS:  # mudança de nameserver do apex = delegação / possível hijack
        return Level.HIGH
    if k == Kind.MAILSEC:  # SPF/DMARC removido = domínio spoofável -> HIGH
        return Level.HIGH if t == EventType.REMOVED else Level.MEDIUM
    if t == EventType.ADDED and k in (Kind.PORT, Kind.SUBDOMAIN):
        return Level.HIGH
    if k == Kind.HTTPSEC:  # postura de headers: mudança importa, resto é baixo
        return Level.MEDIUM if t == EventType.CHANGED else Level.LOW
    if k == Kind.FAVICON:  # pivot de infra: mudança é sinal leve, resto informativo
        return Level.LOW if t == EventType.CHANGED else Level.DEBUG
    if k in (Kind.HTTP, Kind.TLS):
        return Level.LOW if t == EventType.REMOVED else Level.MEDIUM
    if k in (Kind.PORT, Kind.SUBDOMAIN):  # removido ou alterado
        return Level.LOW
    return Level.DEBUG  # dns


@dataclass
class RiskAssessment:
    """Severidade final + o PORQUÊ (regras determinísticas que a elevaram).

    `reasons` vazio = ficou na severidade base. Sempre explicável: cada regra
    contextual que dispara deixa uma frase curta aqui."""
    level: Level
    base: Level
    reasons: list[str] = field(default_factory=list)


def _port_of(e: Event) -> int | None:
    """Porta do evento: do metadata (preenchido no scan) ou parseada da key
    `host:porta`. None se não der pra determinar."""
    p = e.metadata.get("port") if e.metadata else None
    if isinstance(p, int):
        return p
    try:
        return int(str(e.key).rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None


def assess(e: Event) -> RiskAssessment:
    """Severidade CONTEXTUAL, determinística e explicável.

    Parte da base e ELEVA por regras nomeadas (nunca abaixa). Cada regra
    responde 'por que isso virou HIGH/CRITICAL?'. Sem contexto aplicável, a
    severidade é a base — total compatibilidade com o comportamento anterior."""
    base = _base_severity(e)
    level = base
    reasons: list[str] = []

    # Regra 1 — porta administrativa/dados recém-EXPOSTA sobe pra CRITICAL.
    if e.kind == Kind.PORT and e.event_type == EventType.ADDED:
        port = _port_of(e)
        if port in _HIGH_RISK_PORTS:
            level = max(level, Level.CRITICAL)
            reasons.append(f"porta {_HIGH_RISK_PORTS[port]} ({port}) recém-exposta "
                           "— acesso administrativo/dados")

    # Regra 2 — DMARC presente mas em p=none (não bloqueia spoofing) => >= HIGH.
    if e.kind == Kind.MAILSEC and e.event_type != EventType.REMOVED:
        pol = (e.metadata or {}).get("p")
        if (pol is not None and str(pol).lower() == "none") \
                or "p=none" in str(e.new_value or "").lower():
            level = max(level, Level.HIGH)
            reasons.append("DMARC em p=none — não bloqueia spoofing")

    # Regra 3 — takeover é sempre crítico (dá o porquê explícito no alerta).
    if e.kind == Kind.TAKEOVER and e.event_type != EventType.REMOVED:
        level = max(level, Level.CRITICAL)
        svc = (e.metadata or {}).get("service")
        reasons.append(f"subdomain takeover{f' — {svc}' if svc else ''}")

    return RiskAssessment(level=level, base=base, reasons=reasons)


def severity(e: Event) -> Level:
    """Severidade final do evento (contextual). Fonte única para filtro por
    canal, painel e webhook — todos veem a MESMA régua."""
    return assess(e).level


def filter_events(events: list[Event], level: Level) -> list[Event]:
    """Mantém só os eventos com severidade >= level."""
    return [e for e in events if severity(e) >= level]
