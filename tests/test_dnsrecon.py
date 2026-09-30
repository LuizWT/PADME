"""Sinais RED no apex: NS + SPF/DMARC (collector dnsrecon) e severidade."""

import asyncio

import dns.exception
import dns.resolver

from padme.collectors import dnsrecon
from padme.models import Event, EventType, Kind
from padme.risk import Level, severity


class _NS:
    def __init__(self, t):
        self._t = t

    def to_text(self):
        return self._t


class _TXT:
    def __init__(self, s):
        self.strings = [s.encode()]


def _resolver_factory(script):
    class _R:
        lifetime = 0.0

        async def resolve(self, name, rtype):
            v = script.get((name, rtype), "NX")
            if v == "NX":
                raise dns.resolver.NXDOMAIN
            if v == "TIMEOUT":
                raise dns.exception.Timeout
            if v == "NOANSWER":
                raise dns.resolver.NoAnswer
            return v
    return _R


def test_ns_spf_dmarc(monkeypatch):
    script = {
        ("alvo.com", "NS"): [_NS("ns1.reg.com."), _NS("ns2.reg.com.")],
        ("alvo.com", "TXT"): [_TXT("v=spf1 include:_spf.google.com ~all")],
        ("_dmarc.alvo.com", "TXT"): [_TXT("v=DMARC1; p=reject; rua=mailto:x@alvo.com")],
    }
    monkeypatch.setattr(dnsrecon.dns.asyncresolver, "Resolver", _resolver_factory(script))
    cr = asyncio.run(dnsrecon.collect("alvo.com", 5))
    assert cr.ok is True
    ns = {r.value for r in cr.records if r.kind == Kind.NS}
    assert ns == {"ns1.reg.com", "ns2.reg.com"}
    mail = {r.key.rsplit("|", 1)[-1]: r for r in cr.records if r.kind == Kind.MAILSEC}
    assert "SPF" in mail and "DMARC" in mail
    assert mail["DMARC"].metadata["p"] == "reject"
    assert mail["SPF"].value.startswith("v=spf1")


def test_sem_spf_dmarc_nao_emite(monkeypatch):
    # NS ok, mas sem TXT (NXDOMAIN) -> observação definitiva, ok=True, sem MAILSEC
    script = {("alvo.com", "NS"): [_NS("ns1.reg.com.")]}
    monkeypatch.setattr(dnsrecon.dns.asyncresolver, "Resolver", _resolver_factory(script))
    cr = asyncio.run(dnsrecon.collect("alvo.com", 5))
    assert cr.ok is True
    assert not any(r.kind == Kind.MAILSEC for r in cr.records)


def test_timeout_preserva(monkeypatch):
    script = {("alvo.com", "NS"): "TIMEOUT"}
    monkeypatch.setattr(dnsrecon.dns.asyncresolver, "Resolver", _resolver_factory(script))
    cr = asyncio.run(dnsrecon.collect("alvo.com", 5))
    assert cr.ok is False   # falha transitória -> não gera REMOVED


def test_severidade_ns_e_mailsec():
    ns = Event("a.com", EventType.CHANGED, Kind.NS, "a.com|NS|x", "old", "new")
    assert severity(ns) == Level.HIGH
    spf_removed = Event("a.com", EventType.REMOVED, Kind.MAILSEC, "a.com|SPF", "v=spf1", None)
    assert severity(spf_removed) == Level.HIGH        # proteção sumiu = grave
    spf_changed = Event("a.com", EventType.CHANGED, Kind.MAILSEC, "a.com|SPF", "a", "b")
    assert severity(spf_changed) == Level.MEDIUM
