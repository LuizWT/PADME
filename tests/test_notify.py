"""Testes dos notificadores extras (Discord/webhook)."""

from padme.models import Event, EventType, Kind
from padme.notify import format_events_md
from padme.notify.webhook import event_to_dict


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
    # campos de conteúdo
    assert d["severity"] == "critical"
    assert d["kind"] == "takeover"
    assert d["type"] == "added"
    assert d["key"] == "blog.alvo.com"
    assert d["old"] is None and d["new"] == "x"
    # campos de rastreio presentes no contrato (None quando o evento não passou pelo storage)
    assert set(d) >= {"event_id", "scan_id", "detected_at"}


def test_event_to_dict_com_rastreio():
    e = Event("alvo.com", EventType.ADDED, Kind.PORT, "alvo.com:443", None, "open",
              event_id="abc", scan_id="scan1", detected_at="2026-09-26T00:00:00+00:00")
    d = event_to_dict(e)
    assert d["event_id"] == "abc" and d["scan_id"] == "scan1"
    assert d["detected_at"].endswith("+00:00")
