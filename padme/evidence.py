"""Evidência leve e normalizada por evento (§6.3 do roadmap).

"De onde veio esta conclusão?" — sem virar repositório de dumps. A Padmé já
guarda os fatos estruturados no `metadata` de cada Record/Event; aqui apenas os
**projetamos** num objeto pequeno e tipado (`{"type": ..., ...}`), consistente
entre categorias, do jeito que um analista (ou uma automação) quer ler a prova
que sustenta o achado.

É uma FUNÇÃO PURA sobre dados já coletados: nada de I/O, nada de storage novo,
nada de migração. Metadata continua sendo o enriquecimento cru; a evidência é a
sua leitura normalizada ("como isto foi observado"). Quando não há fato de
sustentação (só o `type` sobraria — ex.: um REMOVED cujo record já não existe),
devolve None: melhor sem evidência do que uma evidência vazia/enganosa.
"""

from __future__ import annotations

from .models import Kind


def _ev(d: dict) -> dict | None:
    """Poda None/vazio (mantém 0/False) e exige ao menos um fato além do `type`."""
    out = {k: v for k, v in d.items() if v not in (None, "", [], {})}
    return out if len(out) > 1 else None


def evidence_of(kind: Kind, key: str, value: str | None, metadata: dict | None) -> dict | None:
    """Projeção normalizada da evidência de um record/evento, ou None quando não
    há fato útil. `value` é o resumo humano; `metadata` os fatos crus."""
    md = metadata or {}
    val = value or ""

    if kind == Kind.PORT:
        # state='open' só quando há o fato da porta (um REMOVED não reafirma "open")
        return _ev({"type": "tcp_connect", "port": md.get("port"),
                    "state": "open" if md.get("port") is not None else None,
                    "service": md.get("service"), "product": md.get("product"),
                    "version": md.get("version"), "banner": md.get("banner")})

    if kind == Kind.HTTP:
        return _ev({"type": "http_response", "status": md.get("status"),
                    "server": md.get("server"), "scheme": md.get("scheme"),
                    "location": md.get("location"), "title": md.get("title")})

    if kind == Kind.HTTPSEC:
        return _ev({"type": "http_headers", "missing": md.get("missing"),
                    "present": md.get("present"), "scheme": md.get("scheme")})

    if kind == Kind.TLS:
        return _ev({"type": "tls_handshake", "issuer": md.get("issuer"),
                    "fingerprint": md.get("fingerprint"), "expires_at": md.get("expires_at"),
                    "sans": md.get("sans")})

    if kind == Kind.CERT_EXPIRY:
        return _ev({"type": "tls_cert", "expires_at": md.get("expires_at"),
                    "days_left": md.get("days_left"), "expired": md.get("expired")})

    if kind == Kind.TAKEOVER:
        return _ev({"type": "takeover_check", "cname": md.get("cname"),
                    "service": md.get("service"), "reason": md.get("reason") or val})

    if kind == Kind.NS:
        return _ev({"type": "dns_ns", "nameserver": md.get("nameserver") or val})

    if kind == Kind.MAILSEC:
        # key = "apex|SPF" / "apex|DMARC": o tipo sai da key e a política do valor
        # quando o metadata não veio (ex.: REMOVED — a política que foi removida),
        # como o NS já faz com o nameserver.
        record = md.get("type") or (key.rsplit("|", 1)[-1].lower() if "|" in key else None)
        return _ev({"type": "dns_txt", "record": record,
                    "policy": md.get("policy") or val, "p": md.get("p")})

    if kind == Kind.DNS:
        parts = key.split("|", 2)  # key = "host|TYPE|valor"
        record_type = parts[1] if len(parts) >= 2 else None
        return _ev({"type": "dns_record", "record_type": record_type, "value": val})

    if kind == Kind.FAVICON:
        return _ev({"type": "favicon_hash", "hash": val, "algo": md.get("algo")})

    if kind == Kind.WILDCARD:
        return _ev({"type": "dns_wildcard", "ips": val})

    if kind == Kind.SUBDOMAIN:
        return _ev({"type": "dns_resolve", "liveness": val})

    return None
