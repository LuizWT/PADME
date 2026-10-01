"""Detecção de subdomain takeover.

Um takeover acontece quando um subdomínio aponta (via CNAME) para um serviço
de terceiro que não está mais reivindicado — aí um atacante registra o recurso
e passa a servir conteúdo naquele host. Base dos fingerprints: projeto
comunitário can-i-take-over-xyz.

Fluxo por host (barato por padrão — só faz HTTP se o CNAME casar um serviço):
  1. Resolve o CNAME do host. Sem CNAME -> não é candidato, sai.
  2. Casa o alvo do CNAME contra a base de serviços.
  3. Serviço 'nxdomain': se o alvo do CNAME não resolve (NXDOMAIN) -> vulnerável.
     Serviço com 'fingerprint': busca o corpo HTTP e casa a assinatura (regex)
     de "recurso não reivindicado". `status` vem do upstream: "edge case"
     (reivindicação depende do caso) baixa a confiança do achado.
  4. CNAME para serviço DESCONHECIDO: se o alvo não resolve (NXDOMAIN) E o
     domínio registrável dele também não existe (NS -> NXDOMAIN), qualquer um
     pode registrar esse domínio e passar a responder pelo host -> takeover
     (domínio expirado/nunca registrado). Alvo inexistente dentro de um domínio
     que EXISTE não é reivindicável por terceiro: não é achado.

Só rode contra domínios que você é dono ou tem autorização para testar.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources

import httpx

from ..domains import (
    Availability,
    Rdap,
    check_registrable,
    is_claimable,
)
from ..models import CollectionResult, Kind, Record
from .http import DEFAULT_MAX_BYTES, _fetch_limited

try:
    import dns.asyncresolver
    import dns.resolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


def _load_fingerprints() -> tuple[list[dict], str]:
    """Base de serviços (dado do pacote, não código): revisável e atualizável
    sem mexer no collector. Devolve (serviços, data da última revisão)."""
    raw = resources.files("padme").joinpath("data/takeover_fingerprints.json").read_text("utf-8")
    doc = json.loads(raw)
    return doc["services"], doc.get("reviewed", "")


# nxdomain=True  -> vulnerável quando o alvo do CNAME não resolve
# fingerprint    -> string que o serviço serve quando o recurso não existe
FINGERPRINTS, FINGERPRINTS_REVIEWED = _load_fingerprints()



@lru_cache(maxsize=None)
def _signature(pattern: str) -> re.Pattern:
    """Assinatura de corpo = regex (a base vem do can-i-take-over-xyz, que usa
    regex em parte delas), sem diferenciar maiúsculas."""
    return re.compile(pattern, re.IGNORECASE)


def match_service(cname: str) -> dict | None:
    """Casa o alvo de um CNAME contra a base de serviços, respeitando FRONTEIRA
    DE DOMÍNIO (não substring solta): `c == pat` ou `c` termina em `.pat`.

    Assim `foo.github.io` e `github.io` casam, mas `evilgithub.io` e
    `github.io.attacker.com` NÃO — evitando falso positivo por substring.
    """
    c = cname.lower().rstrip(".")
    best, best_len = None, -1
    for fp in FINGERPRINTS:
        for pat in fp["cnames"]:
            pat = pat.lower().rstrip(".")
            # o sufixo MAIS ESPECÍFICO vence (um domínio amplo de um serviço não
            # pode sombrear o subdomínio específico de outro na base)
            if (c == pat or c.endswith("." + pat)) and len(pat) > best_len:
                best, best_len = fp, len(pat)
    return best


def _dangling_reason(domain: str, av: Availability) -> str:
    """Texto do achado conforme a certeza sobre o domínio registrável."""
    if av == Availability.FREE:
        return f"CNAME dangling: domínio {domain} não registrado (RDAP 404) — registrável agora"
    if av == Availability.PENDING_RELEASE:
        return f"CNAME dangling: domínio {domain} expirado/suspenso (RDAP) — a caminho de liberar"
    return (f"CNAME dangling: domínio {domain} fora da zona do TLD (NXDOMAIN) — "
            "não registrado ou expirado")


async def _domain_unregistered(domain: str, timeout: float) -> bool | None:
    """True = domínio não existe (NXDOMAIN no NS); False = existe; None =
    inconclusivo (timeout/SERVFAIL) — nunca vira achado."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    try:
        await resolver.resolve(domain, "NS")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return False  # nome existe (sem NS próprio: subzona de outro domínio)
    except Exception:
        return None


async def _cname_target(host: str, timeout: float) -> tuple[str | None, bool, bool]:
    """Retorna (alvo do CNAME | None, alvo_resolve, observado_ok).

    observado_ok=False sinaliza que a resolução foi INCONCLUSIVA (timeout /
    SERVFAIL / sem dnspython): nesse caso preservamos qualquer achado anterior
    em vez de removê-lo. resolver que falha nunca vira 'dangling'/takeover.
    """
    if not _HAS_DNS:
        return None, True, False  # não dá pra observar
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    try:
        ans = await resolver.resolve(host, "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None, True, True  # definitivamente sem CNAME -> não é candidato
    except Exception:
        return None, True, False  # timeout/SERVFAIL -> inconclusivo
    target = str(ans[0].target).rstrip(".")
    state = await _resolves(resolver, target)
    if state == "nxdomain":
        return target, False, True   # dangling confirmado (nome não existe)
    if state == "resolves":
        return target, True, True    # tem A/AAAA (ou existe sem endereço) -> não é dangling
    return target, True, False       # inconclusivo (timeout/SERVFAIL) -> não crava dangling


async def _resolves(resolver, target: str) -> str:
    """Estado de resolução do alvo do CNAME: 'resolves' | 'nxdomain' | 'unknown'.

    Checa A E AAAA — um alvo só-IPv6 não pode ser dado como indisponível por
    ausência de A. NXDOMAIN é definitivo (nome inexistente = dangling). NoAnswer
    (nome existe, sem endereço daquele tipo) não é dangling. Timeout/SERVFAIL =
    'unknown' (nunca vira takeover).
    """
    saw_noanswer = False
    for rtype in ("A", "AAAA"):
        try:
            await resolver.resolve(target, rtype)
            return "resolves"
        except dns.resolver.NXDOMAIN:
            return "nxdomain"
        except dns.resolver.NoAnswer:
            saw_noanswer = True
        except Exception:
            return "unknown"  # timeout/SERVFAIL: não classifica como dangling
    # nome existe (NOERROR) mas sem A nem AAAA -> não é dangling de takeover
    return "resolves" if saw_noanswer else "unknown"


async def _body(
    client: httpx.AsyncClient, host: str, cache: dict[str, str] | None = None,
    follow_redirects: bool = False, max_bytes: int = DEFAULT_MAX_BYTES,
    allow_private: bool = False,
) -> tuple[str, bool]:
    """Retorna (corpo, buscado_ok). buscado_ok=False se nenhum esquema respondeu
    (a checagem de fingerprint fica inconclusiva). Corpo limitado a max_bytes."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        if cache is not None and url in cache:  # reaproveita o GET do collector HTTP
            return cache[url], True
        try:
            _, body = await _fetch_limited(client, url, follow_redirects, max_bytes,
                                           allow_private)
            return body, True
        except Exception:
            continue
    return "", False


async def collect_host(
    host: str, client: httpx.AsyncClient, timeout: float,
    cache: dict[str, str] | None = None, follow_redirects: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES, allow_private: bool = False,
    rdap: Rdap | None = None,
) -> CollectionResult:
    target, resolves, cname_ok = await _cname_target(host, timeout)
    if target is None:
        # sem CNAME (definitivo=ok) ou inconclusivo (ok=False, preserva achado)
        return CollectionResult(records=[], ok=cname_ok)
    fp = match_service(target)
    if not fp:
        # serviço desconhecido: só é achado se o alvo não existe E o domínio
        # registrável dele estiver livre para registro (dangling genérico).
        if not cname_ok:
            return CollectionResult(records=[], ok=False)
        if resolves:
            return CollectionResult(records=[], ok=True)
        check = await check_registrable(
            target, lambda d: _domain_unregistered(d, timeout), rdap)
        if check.registrable is None:   # TLD interno/reservado -> não é achado
            return CollectionResult(records=[], ok=True)
        av = check.availability
        if av == Availability.UNKNOWN:
            return CollectionResult(records=[], ok=False)   # inconclusivo -> preserva
        if not is_claimable(av):        # REGISTERED -> delegação lame, não reivindicável
            return CollectionResult(records=[], ok=True)
        reason = _dangling_reason(check.registrable, av)
        service = "domínio não registrado/expirado"
        return CollectionResult(records=[Record(
            kind=Kind.TAKEOVER, key=host, value=f"{service} | {target} | {reason}",
            metadata={"service": service, "cname": target, "reason": reason,
                      "domain": check.registrable, "availability": av.value})], ok=True)

    reason = ""
    ok = True
    if fp["nxdomain"]:
        if not cname_ok:
            ok = False  # resolução do alvo foi inconclusiva -> preserva
        elif not resolves:
            reason = "CNAME dangling (NXDOMAIN)"
    elif fp["fingerprint"]:
        body, fetched = await _body(client, host, cache, follow_redirects, max_bytes,
                                    allow_private)
        if not fetched:
            ok = False  # não conseguimos o corpo -> inconclusivo, preserva
        elif _signature(fp["fingerprint"]).search(body):
            reason = "fingerprint de recurso não reivindicado"

    records = []
    if reason:
        records.append(Record(kind=Kind.TAKEOVER, key=host,
                              value=f"{fp['service']} | {target} | {reason}",
                              metadata={"service": fp["service"], "cname": target, "reason": reason,
                                        "status": fp.get("status", "vulnerable")}))
    return CollectionResult(records=records, ok=ok)
