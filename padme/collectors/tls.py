"""Inspeção de certificado TLS (handshake na porta 443).

Lê emissor, validade e fingerprint. Um certificado renovado, um emissor
diferente ou uma data de expiração próxima são sinais úteis — inclusive
para não deixar um cert expirar sem querer.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl

from ..models import Kind, Record


def _blocking_cert(host: str, port: int, timeout: float) -> dict | None:
    ctx = ssl.create_default_context()
    # Não validamos a cadeia: queremos LER o cert como está, mesmo self-signed.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert()  # pode vir vazio com CERT_NONE
    fp = hashlib.sha256(cert_bin).hexdigest()[:16] if cert_bin else ""
    return {"fp": fp, "cert": cert}


def _name(seq) -> str:
    try:
        d = {k: v for item in seq for (k, v) in item}
        return d.get("organizationName") or d.get("commonName") or ""
    except Exception:
        return ""


async def collect_host(host: str, timeout: float, port: int = 443) -> list[Record]:
    loop = asyncio.get_running_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, _blocking_cert, host, port, timeout),
            timeout=timeout + 2,
        )
    except Exception:
        return []
    if not data:
        return []

    cert = data.get("cert") or {}
    issuer = _name(cert.get("issuer", ()))
    not_after = cert.get("notAfter", "")
    fp = data["fp"]
    value = f"issuer={issuer} | expira={not_after} | fp={fp}".strip()
    return [Record(kind=Kind.TLS, key=f"{host}:{port}", value=value)]
