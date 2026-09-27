"""Fonte ÚNICA dos rótulos e descrições dos eventos.

Antes, Discord e e-mail importavam esses símbolos de `telegram.py` (acoplamento
estranho: canal dependia de internals de outro canal). Agora todos importam
daqui. Cada canal ainda faz a sua renderização (HTML / Markdown / texto puro),
mas os DADOS (marcador, rótulo, ordem, descrição) vêm de um lugar só.
"""

from __future__ import annotations

from ..models import Event, EventType, Kind

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
    Kind.TLS: "TLS",
    Kind.DNS: "DNS",
}

# ordem de exibição: o mais crítico primeiro
KIND_ORDER = [
    Kind.TAKEOVER, Kind.CERT_EXPIRY, Kind.NS, Kind.MAILSEC, Kind.WILDCARD,
    Kind.SUBDOMAIN, Kind.PORT, Kind.HTTP, Kind.TLS, Kind.DNS,
]

# descrição técnica curta por (categoria, tipo de evento)
DESC = {
    Kind.PORT: {"added": "porta abriu", "removed": "porta fechou (não responde mais)", "changed": "porta alterada"},
    Kind.SUBDOMAIN: {"added": "subdomínio novo", "removed": "subdomínio sumiu", "changed": "subdomínio alterado"},
    Kind.HTTP: {"added": "serviço HTTP novo", "removed": "HTTP parou de responder", "changed": "resposta HTTP mudou"},
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
