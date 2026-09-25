"""Testes do engine de diff — o coração do 'o que mudou?'."""

from padme.differ import diff
from padme.models import EventType, Kind


def _state(*pairs):
    return {(k.value, key): val for (k, key, val) in pairs}


def test_added():
    old = _state()
    new = _state((Kind.SUBDOMAIN, "api.x.com", ""))
    events = diff("x.com", old, new)
    assert len(events) == 1
    assert events[0].event_type == EventType.ADDED
    assert events[0].key == "api.x.com"


def test_removed():
    old = _state((Kind.PORT, "x.com:22", "open"))
    new = _state()
    events = diff("x.com", old, new)
    assert len(events) == 1
    assert events[0].event_type == EventType.REMOVED


def test_changed():
    old = _state((Kind.HTTP, "https://x.com", "404 | nginx | "))
    new = _state((Kind.HTTP, "https://x.com", "200 | nginx | Home"))
    events = diff("x.com", old, new)
    assert len(events) == 1
    assert events[0].event_type == EventType.CHANGED
    assert events[0].old_value.startswith("404")
    assert events[0].new_value.startswith("200")


def test_no_change():
    s = _state((Kind.TLS, "x.com:443", "issuer=LE | expira=... | fp=abc"))
    assert diff("x.com", s, dict(s)) == []


def test_mixed():
    old = _state(
        (Kind.SUBDOMAIN, "old.x.com", ""),
        (Kind.PORT, "x.com:80", "open"),
    )
    new = _state(
        (Kind.PORT, "x.com:80", "open"),
        (Kind.SUBDOMAIN, "new.x.com", ""),
    )
    events = diff("x.com", old, new)
    types = sorted(e.event_type.value for e in events)
    assert types == ["added", "removed"]
