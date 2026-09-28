"""Testes da evidência normalizada (§6.3)."""

from padme.evidence import evidence_of
from padme.models import Event, EventType, Kind
from padme.notify.webhook import event_to_dict


def test_port_tcp_connect():
    ev = evidence_of(Kind.PORT, "a.com:3389", "open", {"port": 3389, "banner": "xrdp"})
    assert ev == {"type": "tcp_connect", "state": "open", "port": 3389, "banner": "xrdp"}


def test_http_response_sem_campos_none():
    ev = evidence_of(Kind.HTTP, "https://a.com", "200 | nginx",
                     {"status": 200, "server": "nginx", "scheme": "https",
                      "location": None, "title": ""})
    # location/title vazios são podados
    assert ev == {"type": "http_response", "status": 200, "server": "nginx", "scheme": "https"}


def test_takeover_usa_reason():
    ev = evidence_of(Kind.TAKEOVER, "blog.a.com", "GitHub Pages",
                     {"cname": "x.github.io", "service": "GitHub Pages",
                      "reason": "CNAME dangling (NXDOMAIN)"})
    assert ev["type"] == "takeover_check"
    assert ev["cname"] == "x.github.io" and "NXDOMAIN" in ev["reason"]


def test_dns_record_type_extraido_da_key():
    ev = evidence_of(Kind.DNS, "a.com|A|203.0.113.10", "203.0.113.10", {})
    assert ev == {"type": "dns_record", "record_type": "A", "value": "203.0.113.10"}


def test_cert_expiry():
    ev = evidence_of(Kind.CERT_EXPIRY, "a.com:443", "EXPIRADO",
                     {"expires_at": "2026-10-01T00:00:00+00:00", "days_left": -2, "expired": True})
    assert ev["type"] == "tls_cert" and ev["expired"] is True and ev["days_left"] == -2


def test_kind_sem_evidencia_retorna_none():
    # SUBDOMAIN sem liveness (record antigo) -> None
    assert evidence_of(Kind.SUBDOMAIN, "x.a.com", "", {}) is None


def test_port_removed_sem_fato_nao_afirma_open():
    # REMOVED de porta: metadata vazia -> sem o fato "port", não reafirma "open"
    assert evidence_of(Kind.PORT, "a.com:3389", "open", {}) is None


def test_webhook_inclui_evidence():
    e = Event("a.com", EventType.ADDED, Kind.PORT, "a.com:3389", None, "open",
              metadata={"port": 3389, "banner": "OpenSSH_9.6"})
    d = event_to_dict(e)
    assert "evidence" in d
    assert d["evidence"]["type"] == "tcp_connect" and d["evidence"]["port"] == 3389


def test_webhook_removed_usa_old_value():
    e = Event("a.com", EventType.REMOVED, Kind.DNS, "a.com|A|203.0.113.10",
              "203.0.113.10", None)
    d = event_to_dict(e)
    assert d["evidence"] == {"type": "dns_record", "record_type": "A", "value": "203.0.113.10"}
