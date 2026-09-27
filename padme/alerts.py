"""Amortecimento de flapping.

Uma chave que oscila (added/removed/added…) gera alerta repetido — ruído que faz
você começar a ignorar o Padmé. Aqui a supressão é só de NOTIFICAÇÃO: os eventos
continuam gravados (histórico, painel, tendência); apenas param de ser enviados
enquanto a chave está flapando.
"""

from __future__ import annotations

import time

from .models import Event


def damp_flapping(storage, target: str, events: list[Event],
                  threshold: int, window_minutes: int) -> tuple[list[Event], int]:
    """Devolve (eventos_a_notificar, quantos_suprimidos). Uma chave com
    >= `threshold` eventos na janela é considerada flapping e seus eventos não
    são notificados. threshold <= 0 desliga."""
    if threshold <= 0 or not events:
        return events, 0
    since = time.time() - window_minutes * 60
    counts = storage.recent_event_counts(target, since)
    to_notify = [e for e in events if counts.get((e.kind.value, e.key), 0) < threshold]
    return to_notify, len(events) - len(to_notify)
