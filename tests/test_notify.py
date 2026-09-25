"""Testes dos notificadores extras (Discord/webhook)."""

from padme.notify import format_events_md
from padme.notify.webhook import event_to_dict
from padme.models import Event, EventType, Kind


def _sample():
    return [
        Event("alvo.com", EventType.ADDED, Kind.TAKEOVER, "blog.alvo.com", None, "GitHub Pages | alvo.github.io | fingerprint"),
        Event("alvo.com", EventType.ADDED, Kind.PORT, "alvo.com:8080"),
        Event("alvo.com", EventType.CHANGED, Kind.HTTP, "http://alvo.com", "404 | nginx", "200 | Apache"),
    ]


def test_md_estrutura():
    md = format_events_md("alvo.com", _sample())
    assert "**PADMÉ**" in md
    assert "**TAKEOVER**" in md          # takeover primeiro
    assert md.index("TAKEOVER") < md.index("PORT")
    assert "porta abriu" in md           # descrição técnica
    assert "http://alvo.com" in md       # URL nua (Discord auto-linka)


def test_md_vazio():
    assert format_events_md("alvo.com", []) == ""


def test_event_to_dict():
    e = Event("alvo.com", EventType.ADDED, Kind.TAKEOVER, "blog.alvo.com", None, "x")
    d = event_to_dict(e)
    assert d == {
        "severity": "critical",
        "kind": "takeover",
        "type": "added",
        "key": "blog.alvo.com",
        "old": None,
        "new": "x",
    }
