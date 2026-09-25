"""Teste do formatador de e-mail (texto puro)."""

from padme.notify import format_events_plain
from padme.models import Event, EventType, Kind


def test_plain():
    evs = [
        Event("alvo.com", EventType.ADDED, Kind.PORT, "alvo.com:8080"),
        Event("alvo.com", EventType.CHANGED, Kind.HTTP, "http://alvo.com", "404", "200"),
    ]
    txt = format_events_plain("alvo.com", evs)
    assert "PADMÉ" in txt
    assert "[PORT]" in txt
    assert "porta abriu" in txt
    assert "404 -> 200" in txt
    assert "<" not in txt  # sem HTML


def test_plain_vazio():
    assert format_events_plain("alvo.com", []) == ""
