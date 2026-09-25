"""Testes do aviso de expiração de certificado TLS."""

import asyncio
from datetime import datetime, timedelta, timezone

from padme.collectors import tls
from padme.models import Kind


def _run(days_to_expiry, monkeypatch, threshold=14):
    na = datetime.now(timezone.utc) + timedelta(days=days_to_expiry)

    def fake(host, port, timeout):
        return {"fp": "abc123", "issuer": "Let's Encrypt", "not_after": na}

    monkeypatch.setattr(tls, "_blocking_cert", fake)
    return asyncio.run(tls.collect_host("x.com", 5, cert_expiry_days=threshold))


def _cert_events(recs):
    return [r for r in recs if r.kind == Kind.CERT_EXPIRY]


def test_sempre_emite_tls(monkeypatch):
    recs = _run(90, monkeypatch)
    assert any(r.kind == Kind.TLS for r in recs)


def test_perto_de_expirar(monkeypatch):
    ce = _cert_events(_run(5, monkeypatch))
    assert len(ce) == 1
    assert ce[0].value.startswith("expira")


def test_longe_nao_avisa(monkeypatch):
    assert _cert_events(_run(90, monkeypatch)) == []


def test_ja_expirado(monkeypatch):
    ce = _cert_events(_run(-3, monkeypatch))
    assert len(ce) == 1
    assert "EXPIRADO" in ce[0].value


def test_buckets(monkeypatch):
    # threshold 14 -> buckets 1/7/14; escala conforme aproxima
    assert "<=14d" in _cert_events(_run(10, monkeypatch, threshold=14))[0].value
    assert "<=7d" in _cert_events(_run(5, monkeypatch, threshold=14))[0].value
    assert "<=1d" in _cert_events(_run(1, monkeypatch, threshold=14))[0].value
