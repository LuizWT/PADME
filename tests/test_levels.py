"""Testes dos níveis de notificação."""

from padme.levels import Level, filter_events, parse_level, severity
from padme.models import Event, EventType, Kind


def _ev(kind, etype):
    return Event("alvo.com", etype, kind, "x")


def test_parse_level():
    assert parse_level("high") == Level.HIGH
    assert parse_level("CRITICAL") == Level.CRITICAL
    assert parse_level("3") == Level.HIGH
    assert parse_level("all") == Level.DEBUG
    assert parse_level("lixo") == Level.MEDIUM  # default
    assert parse_level(Level.LOW) == Level.LOW


def test_severity():
    assert severity(_ev(Kind.TAKEOVER, EventType.ADDED)) == Level.CRITICAL
    assert severity(_ev(Kind.PORT, EventType.ADDED)) == Level.HIGH
    assert severity(_ev(Kind.SUBDOMAIN, EventType.ADDED)) == Level.HIGH
    assert severity(_ev(Kind.HTTP, EventType.CHANGED)) == Level.MEDIUM
    assert severity(_ev(Kind.TLS, EventType.ADDED)) == Level.MEDIUM
    assert severity(_ev(Kind.PORT, EventType.REMOVED)) == Level.LOW
    assert severity(_ev(Kind.HTTP, EventType.REMOVED)) == Level.LOW
    assert severity(_ev(Kind.DNS, EventType.ADDED)) == Level.DEBUG


def test_filter():
    events = [
        _ev(Kind.TAKEOVER, EventType.ADDED),   # CRITICAL
        _ev(Kind.PORT, EventType.ADDED),        # HIGH
        _ev(Kind.HTTP, EventType.CHANGED),      # MEDIUM
        _ev(Kind.PORT, EventType.REMOVED),      # LOW
        _ev(Kind.DNS, EventType.ADDED),         # DEBUG
    ]
    assert len(filter_events(events, Level.DEBUG)) == 5
    assert len(filter_events(events, Level.MEDIUM)) == 3
    assert len(filter_events(events, Level.HIGH)) == 2
    assert len(filter_events(events, Level.CRITICAL)) == 1
