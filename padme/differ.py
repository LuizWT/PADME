"""Engine de diff: compara dois estados e produz eventos.

Puramente funcional — recebe dois dicionários {(kind, key): value} e devolve
a lista de mudanças. Fácil de testar isoladamente.
"""

from __future__ import annotations

from .models import Event, EventType, Kind

# Campos SEMÂNTICOS comparáveis por categoria (o que, se mudar, é uma mudança
# real). Metadata de transporte/tempo fica de fora — não é estado semântico.
# Usado só para DETALHAR um CHANGED (o gatilho continua sendo o `value`).
_COMPARABLE_FIELDS = {
    Kind.HTTP: ("status", "server", "title", "location"),
    Kind.HTTPSEC: ("missing",),
    Kind.PORT: ("state", "banner"),
    Kind.TLS: ("issuer", "subject", "expires", "fingerprint"),
    Kind.MAILSEC: ("p",),
}


def comparable_state(kind: Kind, value: str, metadata: dict | None) -> dict:
    """Estado semântico normalizado do record. A partir do metadata quando há
    campos definidos p/ a categoria; senão, cai no `value` (resumo humano)."""
    fields = _COMPARABLE_FIELDS.get(kind)
    md = metadata or {}
    if fields:
        state = {f: md.get(f) for f in fields if md.get(f) is not None}
        if state:
            return state
    return {"value": value}


def field_changes(kind: Kind, old_value: str, old_meta: dict | None,
                  new_value: str, new_meta: dict | None) -> dict:
    """Diff por CAMPO entre dois estados de um mesmo record (para eventos
    CHANGED). Devolve {campo: {'old': ..., 'new': ...}} só dos que mudaram."""
    old_s = comparable_state(kind, old_value, old_meta)
    new_s = comparable_state(kind, new_value, new_meta)
    out: dict = {}
    for f in sorted(set(old_s) | set(new_s)):
        o, n = old_s.get(f), new_s.get(f)
        if o != n:
            out[f] = {"old": o, "new": n}
    return out


def diff(
    target: str,
    old: dict[tuple[str, str], str],
    new: dict[tuple[str, str], str],
) -> list[Event]:
    events: list[Event] = []
    old_keys = set(old)
    new_keys = set(new)

    for (kind, key) in sorted(new_keys - old_keys):
        events.append(
            Event(target, EventType.ADDED, Kind(kind), key, None, new[(kind, key)])
        )

    for (kind, key) in sorted(old_keys - new_keys):
        events.append(
            Event(target, EventType.REMOVED, Kind(kind), key, old[(kind, key)], None)
        )

    for (kind, key) in sorted(old_keys & new_keys):
        if old[(kind, key)] != new[(kind, key)]:
            events.append(
                Event(
                    target,
                    EventType.CHANGED,
                    Kind(kind),
                    key,
                    old[(kind, key)],
                    new[(kind, key)],
                )
            )

    return events
