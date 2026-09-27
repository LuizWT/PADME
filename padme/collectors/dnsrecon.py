"""Sinais de DNS de alto valor no APEX: nameservers (NS) e postura de e-mail
(SPF / DMARC via TXT).

Por que importam (RED):
  - NS: mudança de nameserver do apex pode ser delegação legítima… ou hijack de
    zona. É um evento que você quer ver.
  - SPF/DMARC: se a proteção anti-spoofing SOME (SPF/DMARC removido) ou AFROUXA
    (DMARC p=reject -> p=none), o domínio fica spoofável. Remoção é sinal forte.

Roda no apex (uma vez por alvo). Confiabilidade igual ao collector de DNS:
resposta definitiva (NXDOMAIN/NoAnswer) conta como observação; timeout/SERVFAIL
marca `ok=False` e preserva o estado anterior (não apaga por falha transitória).
"""

from __future__ import annotations

from ..models import CollectionResult, Kind, Record

try:
    import dns.asyncresolver  # type: ignore
    import dns.resolver  # type: ignore

    _HAS_DNS = True
    _DEFINITIVE = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)
except Exception:  # pragma: no cover
    _HAS_DNS = False
    _DEFINITIVE = ()


def _txt_value(rr) -> str:
    """Concatena os fragmentos de um registro TXT (dnspython entrega em bytes)."""
    strings = getattr(rr, "strings", None)
    if strings:
        return b"".join(strings).decode("utf-8", errors="ignore")
    return rr.to_text().strip('"')


async def _txt_find(resolver, name: str, prefix: str) -> tuple[str | None, bool]:
    """Acha o TXT que começa com `prefix` (ex.: 'v=spf1'). Retorna (valor|None, ok).
    ok=False só em erro transitório — NXDOMAIN/NoAnswer = 'definitivamente ausente'."""
    try:
        ans = await resolver.resolve(name, "TXT")
    except _DEFINITIVE:
        return None, True
    except Exception:
        return None, False
    for rr in ans:
        txt = _txt_value(rr)
        if txt.lower().startswith(prefix.lower()):
            return txt, True
    return None, True  # respondeu, mas não há o registro procurado


def _dmarc_policy(txt: str) -> str:
    """Extrai o p= do DMARC (none/quarantine/reject)."""
    for part in txt.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return part[2:].strip().lower()
    return ""


async def collect(apex: str, timeout: float) -> CollectionResult:
    if not _HAS_DNS:
        return CollectionResult(records=[], ok=False)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    records: list[Record] = []
    ok = True

    # nameservers do apex
    try:
        ans = await resolver.resolve(apex, "NS")
        for ns in sorted(a.to_text().rstrip(".") for a in ans):
            records.append(Record(Kind.NS, f"{apex}|NS|{ns}", ns, metadata={"nameserver": ns}))
    except _DEFINITIVE:
        pass  # apex sem NS é raro, mas é resposta definitiva
    except Exception:
        ok = False

    # SPF (TXT no apex)
    spf, spf_ok = await _txt_find(resolver, apex, "v=spf1")
    ok = ok and spf_ok
    if spf:
        records.append(Record(Kind.MAILSEC, f"{apex}|SPF", spf, metadata={"type": "spf", "policy": spf}))

    # DMARC (TXT em _dmarc.apex)
    dmarc, dmarc_ok = await _txt_find(resolver, f"_dmarc.{apex}", "v=DMARC1")
    ok = ok and dmarc_ok
    if dmarc:
        p = _dmarc_policy(dmarc)
        records.append(Record(Kind.MAILSEC, f"{apex}|DMARC", dmarc,
                              metadata={"type": "dmarc", "policy": dmarc, "p": p}))

    return CollectionResult(records=records, ok=ok)
