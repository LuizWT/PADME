"""Níveis de notificação (estilo log level) para o retorno via Telegram.

O terminal sempre mostra tudo. O nível define o LIMIAR mínimo de severidade
que é enviado ao Telegram — do mais barulhento ao mais crítico:

    DEBUG    (0)  tudo, inclusive registros DNS
    LOW      (1)  remoções e mudanças menores
    MEDIUM   (2)  HTTP/TLS mudou, serviço novo   <- padrão
    HIGH     (3)  porta nova aberta / subdomínio novo (superfície cresceu)
    CRITICAL (4)  só subdomain takeover

Severidade de cada evento (kind + tipo):
    takeover (novo/alterado)  -> CRITICAL
    cert_expiry (novo/escala) -> HIGH
    wildcard ADDED            -> HIGH
    port/subdomain ADDED      -> HIGH
    http/tls (add/changed)    -> MEDIUM
    http/tls REMOVED,
      port/subdomain removido -> LOW
    RESOLUÇÃO (takeover/cert
      REMOVED, wildcard some
      ou troca de IP)         -> LOW   (boa notícia não é alerta)
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
    # REMOVED de um PROBLEMA = o problema foi resolvido (takeover corrigido,
    # cert renovado): registra, mas não dispara alerta com a gravidade do problema.
    if k == Kind.TAKEOVER:
        return Level.LOW if t == EventType.REMOVED else Level.CRITICAL
    if k == Kind.CERT_EXPIRY:
        return Level.LOW if t == EventType.REMOVED else Level.HIGH
    if k == Kind.WILDCARD:
        # curinga NOVO é o achado; troca do IP do catch-all (rotação de CDN) ou
        # curinga removido não é superfície nova.
        return Level.HIGH if t == EventType.ADDED else Level.LOW
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


class Confidence(IntEnum):
    """Confiança na OBSERVAÇÃO/classificação — dimensão INDEPENDENTE da severidade.

        severity   = quão relevante/impactante é
        confidence = quão confiável é a observação que sustenta a conclusão

    A maioria dos sinais do Padmé é observação direta (connect TCP, resposta DNS,
    handshake TLS) => CONFIRMED. Inferências (dangling por NXDOMAIN) ficam abaixo.
    Ganha mais nuance quando entrarem provedores externos de discovery."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CONFIRMED = 3


# Portas de acesso remoto x portas de dados (para o código de razão correto).
_DATA_PORTS = {1433, 2049, 3306, 5432, 5984, 6379, 9200, 11211, 27017}

# Reason codes estruturados (estáveis p/ webhook/n8n/relatório) + rótulo humano.
NEW_OPEN_PORT = "NEW_OPEN_PORT"
REMOTE_ACCESS_SERVICE = "REMOTE_ACCESS_SERVICE"
DATA_SERVICE = "DATA_SERVICE"
INTERNET_EXPOSED_ASSET = "INTERNET_EXPOSED_ASSET"
CRITICAL_ASSET = "CRITICAL_ASSET"
FORBIDDEN_PORT = "FORBIDDEN_PORT"
UNEXPECTED_PORT = "UNEXPECTED_PORT"
SUBDOMAIN_TAKEOVER = "SUBDOMAIN_TAKEOVER"
DMARC_NOT_ENFORCED = "DMARC_NOT_ENFORCED"
MAIL_PROTECTION_REMOVED = "MAIL_PROTECTION_REMOVED"
NAMESERVER_CHANGED = "NAMESERVER_CHANGED"
CERT_EXPIRING = "CERT_EXPIRING"
ISSUE_RESOLVED = "ISSUE_RESOLVED"

REASON_LABEL = {
    NEW_OPEN_PORT: "porta aberta nova",
    REMOTE_ACCESS_SERVICE: "serviço de acesso remoto",
    DATA_SERVICE: "serviço de dados exposto",
    INTERNET_EXPOSED_ASSET: "ativo exposto à Internet",
    CRITICAL_ASSET: "ativo crítico",
    FORBIDDEN_PORT: "porta proibida pela política",
    UNEXPECTED_PORT: "porta fora do estado esperado",
    SUBDOMAIN_TAKEOVER: "subdomain takeover",
    DMARC_NOT_ENFORCED: "DMARC não bloqueia spoofing (p=none)",
    MAIL_PROTECTION_REMOVED: "proteção de e-mail removida",
    NAMESERVER_CHANGED: "nameserver alterado (delegação/hijack)",
    CERT_EXPIRING: "certificado expirando",
    ISSUE_RESOLVED: "problema resolvido",
}


@dataclass
class RiskAssessment:
    """Resultado da avaliação de risco: severidade final, base, CONFIANÇA,
    a regra que decidiu (`rule_id`) e os `reasons` (CÓDIGOS estruturados).

    Determinístico e explicável: sempre dá pra responder 'por que virou X?'.
    `reasons` vazio + level==base = ficou na régua base (compat total)."""
    level: Level
    base: Level
    confidence: Confidence = Confidence.CONFIRMED
    rule_id: str | None = None
    reasons: list[str] = field(default_factory=list)

    def reason_labels(self) -> list[str]:
        """Razões em texto humano (p/ painel/notificação)."""
        return [REASON_LABEL.get(c, c) for c in self.reasons]


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


def _confidence(e: Event) -> Confidence:
    """Confiança na observação. Observação direta = CONFIRMED; takeover por
    inferência (dangling via NXDOMAIN, sem fingerprint) = HIGH."""
    if e.kind == Kind.TAKEOVER:
        reason = str((e.metadata or {}).get("reason", "")).lower()
        return Confidence.CONFIRMED if "fingerprint" in reason else Confidence.HIGH
    return Confidence.CONFIRMED


def assess(e: Event) -> RiskAssessment:
    """Severidade CONTEXTUAL, determinística e explicável (item risk engine).

    Parte da base e ELEVA por regras nomeadas (nunca abaixa), usando o contexto
    de ativo carimbado no evento (`_context`: exposure/criticality/expected/
    forbidden ports). Sem contexto, comporta-se como a régua base — compat total."""
    base = _base_severity(e)
    level = base
    reasons: list[str] = []
    rule_id: str | None = None
    ctx = (e.metadata or {}).get("_context") or {}
    exposure = ctx.get("exposure")
    criticality = ctx.get("criticality")
    expected = set(ctx.get("expected_ports") or [])
    forbidden = set(ctx.get("forbidden_ports") or [])

    # ── PORTAS ────────────────────────────────────────────────────────────
    if e.kind == Kind.PORT and e.event_type == EventType.ADDED:
        reasons.append(NEW_OPEN_PORT)
        port = _port_of(e)
        if port in _HIGH_RISK_PORTS:
            reasons.append(DATA_SERVICE if port in _DATA_PORTS else REMOTE_ACCESS_SERVICE)
            level = max(level, Level.CRITICAL)   # serviço admin/dados novo = crítico
            rule_id = "high-risk-port-added"
        if exposure == "internet":
            reasons.append(INTERNET_EXPOSED_ASSET)
        if port is not None and port in forbidden:   # política: porta proibida
            reasons.append(FORBIDDEN_PORT)
            level = max(level, Level.CRITICAL)
            rule_id = "forbidden-port-open"
        elif port is not None and expected and port not in expected:  # fora do esperado
            reasons.append(UNEXPECTED_PORT)
            level = max(level, Level.HIGH)
            rule_id = rule_id or "unexpected-port-open"

    # ── TAKEOVER ──────────────────────────────────────────────────────────
    if e.kind == Kind.TAKEOVER and e.event_type != EventType.REMOVED:
        reasons.append(SUBDOMAIN_TAKEOVER)
        level = max(level, Level.CRITICAL)
        rule_id = rule_id or "subdomain-takeover"

    # ── E-MAIL (SPF/DMARC) ────────────────────────────────────────────────
    if e.kind == Kind.MAILSEC:
        if e.event_type == EventType.REMOVED:
            reasons.append(MAIL_PROTECTION_REMOVED)   # base já é HIGH
        else:
            pol = ctx.get("_dmarc_p") or (e.metadata or {}).get("p")
            if (pol is not None and str(pol).lower() == "none") \
                    or "p=none" in str(e.new_value or "").lower():
                reasons.append(DMARC_NOT_ENFORCED)
                level = max(level, Level.HIGH)
                rule_id = rule_id or "dmarc-p-none"

    # ── NS / CERT (anotação explicativa; não muda o nível base) ───────────
    if e.kind == Kind.NS:
        reasons.append(NAMESERVER_CHANGED)
    if e.kind == Kind.CERT_EXPIRY and e.event_type != EventType.REMOVED:
        reasons.append(CERT_EXPIRING)
    if e.kind in (Kind.TAKEOVER, Kind.CERT_EXPIRY) and e.event_type == EventType.REMOVED:
        reasons.append(ISSUE_RESOLVED)

    # ── contexto do ativo (anotação transversal) ─────────────────────────
    if criticality == "critical" and level >= Level.MEDIUM:
        reasons.append(CRITICAL_ASSET)

    return RiskAssessment(level=level, base=base, confidence=_confidence(e),
                          rule_id=rule_id, reasons=reasons)


def severity(e: Event) -> Level:
    """Severidade final do evento (contextual). Fonte única para filtro por
    canal, painel e webhook — todos veem a MESMA régua."""
    return assess(e).level


def filter_events(events: list[Event], level: Level) -> list[Event]:
    """Mantém só os eventos com severidade >= level."""
    return [e for e in events if severity(e) >= level]
