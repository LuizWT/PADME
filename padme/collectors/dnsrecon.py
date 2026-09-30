"""Sinais de DNS de alto valor no APEX: nameservers (NS) e postura de e-mail
(SPF / DMARC via TXT).

Por que importam (RED):
  - NS: mudança de nameserver do apex pode ser delegação legítima… ou hijack de
    zona. É um evento que você quer ver.
  - SPF/DMARC: se a proteção anti-spoofing SOME (SPF/DMARC removido) ou AFROUXA
    (DMARC p=reject -> p=none), o domínio fica spoofável. Remoção é sinal forte.

SPF é avaliado de forma EFETIVA (include/redirect seguidos, limite de 10
consultas) e vira um registro próprio (`apex|SPF-EFFECTIVE`) — ver mailpolicy.

Roda no apex (uma vez por alvo). Confiabilidade igual ao collector de DNS:
resposta definitiva (NXDOMAIN/NoAnswer) conta como observação; timeout/SERVFAIL
marca `ok=False` e preserva o estado anterior (não apaga por falha transitória).
"""

from __future__ import annotations

from ..mailpolicy import (
    SPF_EFFECTIVE_SUFFIX,
    SpfInconclusive,
    SpfVerdict,
    dmarc_tag,
    is_spf,
    spf_all_qualifier,
    spf_effective,
)
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


async def _txt_matching(resolver, name: str, pred) -> list[str] | None:
    """TXTs de `name` que passam em `pred`, ordenados (a ordem do DNS é
    arbitrária: sem ordenar, dois registros fariam o valor oscilar).
    [] = definitivamente ausente (NXDOMAIN/NoAnswer); None = erro transitório."""
    try:
        ans = await resolver.resolve(name, "TXT")
    except _DEFINITIVE:
        return []
    except Exception:
        return None
    return sorted(t for t in (_txt_value(rr) for rr in ans) if pred(t))


def _is_dmarc(txt: str) -> bool:
    return txt.strip().lower().startswith("v=dmarc1")


async def _spf_records(apex: str, resolver) -> tuple[list[Record], bool]:
    """TXT bruto do SPF + registro de POSTURA EFETIVA (include/redirect
    seguidos). O efetivo é um registro próprio porque um `include:` pode virar
    `+all` sem o TXT do apex mudar — e só mudança de valor gera evento."""
    spfs = await _txt_matching(resolver, apex, is_spf)
    if spfs is None:
        return [], False
    if not spfs:
        return [], True
    raw = " | ".join(spfs)
    out = [Record(Kind.MAILSEC, f"{apex}|SPF", raw,
                  metadata={"type": "spf", "policy": raw, "records": len(spfs),
                            "all": spf_all_qualifier(spfs[0]) if len(spfs) == 1 else ""})]

    async def fetch(domain: str) -> list[str]:
        found = await _txt_matching(resolver, domain, is_spf)
        if found is None:
            raise SpfInconclusive(domain)
        return found

    if len(spfs) > 1:  # RFC 7208 §4.5: mais de um registro = permerror
        verdict = SpfVerdict("permerror", f"{apex} com {len(spfs)} registros SPF")
    else:
        try:
            verdict = await spf_effective(spfs[0], fetch)
        except SpfInconclusive:
            return out, False   # cadeia sem resposta: preserva a postura anterior
    out.append(Record(Kind.MAILSEC, f"{apex}{SPF_EFFECTIVE_SUFFIX}", verdict.value,
                      metadata={"type": "spf-effective", "policy": verdict.value,
                                "result": verdict.result, "via": verdict.via,
                                "lookups": verdict.lookups}))
    return out, True


async def _dmarc_record(apex: str, resolver) -> tuple[list[Record], bool]:
    recs = await _txt_matching(resolver, f"_dmarc.{apex}", _is_dmarc)
    if recs is None:
        return [], False
    if not recs:
        return [], True
    raw = " | ".join(recs)
    md = {"type": "dmarc", "policy": raw, "records": len(recs)}
    md.update({t: v for t in ("p", "sp", "pct", "t") if (v := dmarc_tag(recs[0], t))})
    return [Record(Kind.MAILSEC, f"{apex}|DMARC", raw, metadata=md)], True


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

    for part in (_spf_records, _dmarc_record):   # SPF (+ efetivo) e DMARC
        recs, part_ok = await part(apex, resolver)
        records.extend(recs)
        ok = ok and part_ok

    return CollectionResult(records=records, ok=ok)
