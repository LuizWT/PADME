"""Testes dos SANs do certificado no diff semântico + evidência (§5.3)."""

import datetime

import pytest

from padme.differ import field_changes
from padme.evidence import evidence_of
from padme.models import Kind

cryptography = pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from padme.collectors.tls import _issuer_and_expiry  # noqa: E402


def _cert_der(sans: list[str]) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_extrai_sans_ordenados_e_normalizados():
    der = _cert_der(["B.example.com", "a.example.com", "a.example.com"])
    _issuer, _exp, sans = _issuer_and_expiry(der)
    assert sans == ["a.example.com", "b.example.com"]   # minúsculo, ordenado, sem dup


def test_field_changes_detecta_san_nova():
    old = {"issuer": "LE", "fingerprint": "aa", "sans": ["a.x.com"]}
    new = {"issuer": "LE", "fingerprint": "bb", "sans": ["a.x.com", "vpn.x.com"]}
    ch = field_changes(Kind.TLS, "issuer=LE", old, "issuer=LE", new)
    assert "sans" in ch
    assert "vpn.x.com" in str(ch["sans"]["new"])


def test_evidence_inclui_sans():
    ev = evidence_of(Kind.TLS, "x.com:443", "issuer=LE",
                     {"issuer": "LE", "fingerprint": "aa", "sans": ["a.x.com", "b.x.com"]})
    assert ev["type"] == "tls_handshake"
    assert ev["sans"] == ["a.x.com", "b.x.com"]
