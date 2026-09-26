"""Inspeção de certificado TLS (handshake na porta 443).

Lê emissor, validade e fingerprint, e — se o certificado estiver perto de
expirar (ou já expirado) — emite um evento `CERT_EXPIRY` para você renovar a
tempo.

O parsing do certificado usa `cryptography` (parseia o DER direto), então
funciona mesmo com cert self-signed, hostname divergente ou já expirado —
casos em que o `ssl.getpeercert()` volta vazio.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from datetime import datetime, timezone

from ..models import CollectionResult, Kind, Record

log = logging.getLogger("padme")

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


def _issuer_and_expiry(cert_bin: bytes) -> tuple[str, datetime | None]:
    if not (_HAS_CRYPTO and cert_bin):
        return "", None
    try:
        cert = x509.load_der_x509_certificate(cert_bin)
    except Exception as exc:  # noqa: BLE001 — observável, mas não derruba o scan
        log.debug("TLS: falha ao parsear certificado (%s)", type(exc).__name__)
        return "", None
    issuer = ""
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = cert.issuer.get_attributes_for_oid(oid)
        if attrs:
            issuer = attrs[0].value
            break
    # not_valid_after_utc em cryptography >= 42; fallback pro naive (UTC)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        na = cert.not_valid_after
        not_after = na.replace(tzinfo=timezone.utc)
    return issuer, not_after


def _blocking_cert(host: str, port: int, timeout: float) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
    if not cert_bin:
        return None
    fp = hashlib.sha256(cert_bin).hexdigest()[:16]
    issuer, not_after = _issuer_and_expiry(cert_bin)
    return {"fp": fp, "issuer": issuer, "not_after": not_after}


async def collect_host(
    host: str, timeout: float, port: int = 443, cert_expiry_days: int = 14
) -> CollectionResult:
    loop = asyncio.get_running_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, _blocking_cert, host, port, timeout),
            timeout=timeout + 2,
        )
    except ConnectionRefusedError:
        # nada escutando em 443 -> observação definitiva de ausência (ok, vazio)
        return CollectionResult(records=[], ok=True)
    except (asyncio.TimeoutError, TimeoutError):
        return CollectionResult(records=[], ok=False)  # transitório: preserva
    except ssl.SSLError:
        return CollectionResult(records=[], ok=False)  # handshake falhou: preserva
    except Exception:
        return CollectionResult(records=[], ok=False)  # rede/erro: preserva
    if not data:
        # conectou mas sem cert legível -> não removemos por isso (preserva)
        return CollectionResult(records=[], ok=False)

    issuer = data["issuer"]
    not_after = data["not_after"]
    fp = data["fp"]
    date_str = not_after.strftime("%Y-%m-%d") if not_after else "?"
    if not issuer or not_after is None:
        # conectou e leu o cert, mas o parser não extraiu tudo: registra pra
        # diagnóstico (sem vazar dado sensível) em vez de engolir em silêncio.
        log.debug("[%s:%d] TLS: cert parcial (issuer=%s expira=%s)",
                  host, port, bool(issuer), "?" if not_after is None else "ok")

    records = [
        Record(kind=Kind.TLS, key=f"{host}:{port}",
               value=f"issuer={issuer} | expira={date_str} | fp={fp}".strip())
    ]

    # aviso de expiração — valor por BUCKET: estável dentro da faixa (1 aviso),
    # e escala (evento CHANGED) quando cruza 7d e 1d.
    if not_after is not None:
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            records.append(Record(Kind.CERT_EXPIRY, f"{host}:{port}", f"EXPIRADO em {date_str}"))
        elif days_left <= cert_expiry_days:
            buckets = sorted({b for b in (1, 7, cert_expiry_days) if b <= cert_expiry_days})
            bucket = next(b for b in buckets if days_left <= b)
            records.append(Record(Kind.CERT_EXPIRY, f"{host}:{port}", f"expira em <={bucket}d ({date_str})"))

    return CollectionResult(records=records, ok=True)
