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

from ..domains import Rdap, check_registrable
from ..mailpolicy import (
    SPF_EFFECTIVE_SUFFIX,
    SPF_ORPHAN_SUFFIX,
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


async def _ns_nxdomain(resolver, domain: str) -> bool | None:
    """NS do domínio: True NXDOMAIN (fora da zona) / False existe / None incerto."""
    try:
        await resolver.resolve(domain, "NS")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return False   # a zona existe (sem NS próprio: subzona de outro domínio)
    except Exception:
        return None


async def _mech_exists(resolver, host: str, rtype: str) -> bool | None:
    """a/mx/ptr/exists: True tem registros / False void / None incerto (RFC §4.6.4)."""
    try:
        ans = await resolver.resolve(host, rtype)
        return len(ans) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        return None


async def _spf_records(apex: str, resolver, rdap: Rdap | None) -> tuple[list[Record], bool]:
    """TXT bruto do SPF + registro de POSTURA EFETIVA (include/redirect
    seguidos) + registro(s) de include ÓRFÃO (domínio registrável livre). O
    efetivo é um registro próprio porque um `include:` pode virar `+all` sem o
    TXT do apex mudar — e só mudança de valor gera evento."""
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

    async def availing(target: str):
        return await check_registrable(target, lambda d: _ns_nxdomain(resolver, d), rdap)

    async def mech_exists(host: str, rtype: str) -> bool | None:
        return await _mech_exists(resolver, host, rtype)

    if len(spfs) > 1:  # RFC 7208 §4.5: mais de um registro = permerror
        verdict = SpfVerdict("permerror", f"{apex} com {len(spfs)} registros SPF")
    else:
        try:
            verdict = await spf_effective(spfs[0], fetch, domain=apex,
                                          availing=availing, mech_exists=mech_exists)
        except SpfInconclusive:
            return out, False   # cadeia sem resposta: preserva a postura anterior
    out.append(Record(Kind.MAILSEC, f"{apex}{SPF_EFFECTIVE_SUFFIX}", verdict.value,
                      metadata={"type": "spf-effective", "policy": verdict.value,
                                "result": verdict.result, "via": verdict.via,
                                "lookups": verdict.lookups}))
    for orphan in verdict.orphans:   # 1 registro por domínio registrável livre
        out.append(Record(
            Kind.MAILSEC, f"{apex}{SPF_ORPHAN_SUFFIX}|{orphan.registrable}",
            f"{orphan.registrable} ({orphan.availability}) via {orphan.target}",
            metadata={"type": "spf-orphan", "registrable": orphan.registrable,
                      "target": orphan.target, "availability": orphan.availability}))
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


async def collect(apex: str, timeout: float, rdap: Rdap | None = None) -> CollectionResult:
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

    spf_recs, spf_ok = await _spf_records(apex, resolver, rdap)   # SPF + efetivo + órfãos
    dmarc_recs, dmarc_ok = await _dmarc_record(apex, resolver)
    records.extend(spf_recs + dmarc_recs)
    ok = ok and spf_ok and dmarc_ok

    return CollectionResult(records=records, ok=ok)
