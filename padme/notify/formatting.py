"""Fonte ÚNICA dos rótulos e descrições dos eventos.

Antes, Discord e e-mail importavam esses símbolos de `telegram.py` (acoplamento
estranho: canal dependia de internals de outro canal). Agora todos importam
daqui. Cada canal ainda faz a sua renderização (HTML / Markdown / texto puro),
mas os DADOS (marcador, rótulo, ordem, descrição) vêm de um lugar só.
"""

from __future__ import annotations

from ..models import Event, EventType, Kind
from ..risk import Confidence, assess

MARK = {EventType.ADDED: "+", EventType.REMOVED: "-", EventType.CHANGED: "~"}

KIND_LABEL = {
    Kind.TAKEOVER: "TAKEOVER",
    Kind.CERT_EXPIRY: "CERT",
    Kind.NS: "NS",
    Kind.MAILSEC: "E-MAIL",
    Kind.WILDCARD: "WILDCARD",
    Kind.SUBDOMAIN: "SUBDOMAIN",
    Kind.PORT: "PORT",
    Kind.HTTP: "HTTP",
    Kind.HTTPSEC: "HEADERS",
    Kind.FAVICON: "FAVICON",
    Kind.TLS: "TLS",
    Kind.DNS: "DNS",
}

# ordem de exibição: o mais crítico primeiro
KIND_ORDER = [
    Kind.TAKEOVER, Kind.CERT_EXPIRY, Kind.NS, Kind.MAILSEC, Kind.WILDCARD,
    Kind.SUBDOMAIN, Kind.PORT, Kind.HTTP, Kind.HTTPSEC, Kind.FAVICON, Kind.TLS, Kind.DNS,
]

# descrição técnica curta por (categoria, tipo de evento)
DESC = {
    Kind.PORT: {"added": "porta abriu", "removed": "porta fechou (não responde mais)", "changed": "porta alterada"},
    Kind.SUBDOMAIN: {"added": "subdomínio novo", "removed": "subdomínio sumiu", "changed": "subdomínio alterado"},
    Kind.HTTP: {"added": "serviço HTTP novo", "removed": "HTTP parou de responder", "changed": "resposta HTTP mudou"},
    Kind.HTTPSEC: {"added": "postura de headers registrada", "removed": "endpoint não avaliado", "changed": "headers de segurança mudaram"},
    Kind.FAVICON: {"added": "favicon novo (pivot de infra)", "removed": "favicon removido", "changed": "favicon mudou (troca de infra/serviço)"},
    Kind.TLS: {"added": "certificado novo", "removed": "TLS parou de responder", "changed": "certificado alterado"},
    Kind.DNS: {"added": "registro novo", "removed": "registro removido", "changed": "registro alterado"},
    Kind.NS: {"added": "nameserver novo", "removed": "nameserver removido", "changed": "nameserver alterado (delegação / possível hijack)"},
    Kind.MAILSEC: {"added": "proteção de e-mail adicionada", "removed": "proteção de e-mail REMOVIDA (domínio spoofável)", "changed": "política de e-mail (SPF/DMARC) alterada"},
    Kind.TAKEOVER: {"added": "possível subdomain takeover", "removed": "takeover resolvido", "changed": "takeover alterado"},
    Kind.CERT_EXPIRY: {"added": "certificado expira em breve", "removed": "certificado renovado", "changed": "situação do certificado mudou"},
    Kind.WILDCARD: {"added": "wildcard DNS ativo (enumeração ativa não confiável)", "removed": "wildcard DNS não responde mais", "changed": "IPs do wildcard mudaram"},
}


def tally(events: list[Event]) -> str:
    """Resumo '+N -N ~N' (só os tipos presentes)."""
    counts = {t: 0 for t in EventType}
    for e in events:
        counts[e.event_type] += 1
    return " ".join(f"{MARK[t]}{counts[t]}" for t in EventType if counts[t])


def group_by_kind(events: list[Event]) -> list[tuple[Kind, list[Event]]]:
    """Agrupa por categoria na KIND_ORDER, cada grupo ordenado por (tipo, key)."""
    by_kind: dict[Kind, list[Event]] = {}
    for e in events:
        by_kind.setdefault(e.kind, []).append(e)
    out: list[tuple[Kind, list[Event]]] = []
    for kind in KIND_ORDER:
        group = by_kind.get(kind)
        if not group:
            continue
        group.sort(key=lambda ev: (ev.event_type.value, ev.key))
        out.append((kind, group))
    return out


def desc(e: Event) -> str:
    """Descrição técnica curta do evento (ou '' se não houver)."""
    return DESC.get(e.kind, {}).get(e.event_type.value, "")


def risk_suffix(e: Event) -> str:
    """Anexo curto com o PORQUÊ do risco — só quando o evento foi ELEVADO pelo
    contexto ou a confiança não é CONFIRMED (mantém o alerta comum enxuto).
    Texto puro, seguro em HTML e Markdown (sem dado de usuário)."""
    r = assess(e)
    if r.level <= r.base and r.confidence == Confidence.CONFIRMED:
        return ""
    parts = []
    if r.reasons:
        parts.append("⚠ " + ", ".join(r.reason_labels()))
    if r.confidence != Confidence.CONFIRMED:
        parts.append(f"confiança {r.confidence.name.lower()}")
    return (" · " + " · ".join(parts)) if parts else ""


def dns_parts(e: Event) -> tuple[str, str, str]:
    """(host, tipo, valor exibido) de um evento DNS. Key atual `host|TIPO` (o
    valor é o conjunto; CHANGED mostra antigo → novo). Key antiga
    `host|TIPO|valor` (histórico, fila de reenvio) continua legível."""
    parts = e.key.split("|", 2)
    host = parts[0]
    rtype = parts[1] if len(parts) > 1 else ""
    if len(parts) == 3:
        return host, rtype, parts[2]
    if e.event_type == EventType.CHANGED:
        return host, rtype, f"{e.old_value} → {e.new_value}"
    val = e.old_value if e.event_type == EventType.REMOVED else e.new_value
    return host, rtype, val or ""
