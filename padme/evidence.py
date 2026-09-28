"""Evidência leve e normalizada por evento (§6.3 do roadmap).

"De onde veio esta conclusão?" — sem virar repositório de dumps. A Padmé já
guarda os fatos estruturados no `metadata` de cada Record/Event; aqui apenas os
**projetamos** num objeto pequeno e tipado (`{"type": ..., ...}`), consistente
entre categorias, do jeito que um analista (ou uma automação) quer ler a prova
que sustenta o achado.

É uma FUNÇÃO PURA sobre dados já coletados: nada de I/O, nada de storage novo,
nada de migração. Metadata continua sendo o enriquecimento cru; a evidência é a
sua leitura normalizada ("como isto foi observado").
"""

from __future__ import annotations

from .models import Kind


def _compact(d: dict) -> dict:
    """Remove chaves com valor None/vazio (mantém 0 e False)."""
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


def evidence_of(kind: Kind, key: str, value: str | None, metadata: dict | None) -> dict | None:
    """Projeção normalizada da evidência de um record/evento, ou None quando não
    há uma forma útil. `value` é o resumo humano; `metadata` os fatos crus."""
    md = metadata or {}
    val = value or ""

    if kind == Kind.PORT:
        return _compact({"type": "tcp_connect", "state": "open",
                         "port": md.get("port"), "banner": md.get("banner")})

    if kind == Kind.HTTP:
        return _compact({"type": "http_response", "status": md.get("status"),
                         "server": md.get("server"), "scheme": md.get("scheme"),
                         "location": md.get("location"), "title": md.get("title")})

    if kind == Kind.HTTPSEC:
        return _compact({"type": "http_headers", "missing": md.get("missing"),
                         "present": md.get("present"), "scheme": md.get("scheme")})

    if kind == Kind.TLS:
        return _compact({"type": "tls_handshake", "issuer": md.get("issuer"),
                         "fingerprint": md.get("fingerprint"),
                         "expires_at": md.get("expires_at")})

    if kind == Kind.CERT_EXPIRY:
        return _compact({"type": "tls_cert", "expires_at": md.get("expires_at"),
                         "days_left": md.get("days_left"), "expired": md.get("expired")})

    if kind == Kind.TAKEOVER:
        return _compact({"type": "takeover_check", "cname": md.get("cname"),
                         "service": md.get("service"), "reason": md.get("reason") or val})

    if kind == Kind.NS:
        return _compact({"type": "dns_ns", "nameserver": md.get("nameserver") or val})

    if kind == Kind.MAILSEC:
        return _compact({"type": "dns_txt", "record": md.get("type"),
                         "policy": md.get("policy"), "p": md.get("p")})

    if kind == Kind.DNS:
        # key = "host|TYPE|valor"
        parts = key.split("|", 2)
        record_type = parts[1] if len(parts) >= 2 else None
        return _compact({"type": "dns_record", "record_type": record_type, "value": val})

    if kind == Kind.FAVICON:
        return _compact({"type": "favicon_hash", "hash": val, "algo": md.get("algo")})

    if kind == Kind.WILDCARD:
        return _compact({"type": "dns_wildcard", "ips": val})

    if kind == Kind.SUBDOMAIN:
        # value = 'live' | 'quiet' (liveness); vazio em records antigos -> sem evidência
        return {"type": "dns_resolve", "liveness": val} if val else None

    return None
