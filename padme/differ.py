"""Engine de diff: compara dois estados e produz eventos.

Puramente funcional — recebe dois dicionários {(kind, key): value} e devolve
a lista de mudanças. Fácil de testar isoladamente.
"""

from __future__ import annotations

from .models import Event, EventType, Kind


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
