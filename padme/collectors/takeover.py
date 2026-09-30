"""Detecção de subdomain takeover.

Um takeover acontece quando um subdomínio aponta (via CNAME) para um serviço
de terceiro que não está mais reivindicado — aí um atacante registra o recurso
e passa a servir conteúdo naquele host. Base dos fingerprints: projeto
comunitário can-i-take-over-xyz.

Fluxo por host (barato por padrão — só faz HTTP se o CNAME casar um serviço):
  1. Resolve o CNAME do host. Sem CNAME -> não é candidato, sai.
  2. Casa o alvo do CNAME contra a base de serviços.
  3. Serviço 'nxdomain': se o alvo do CNAME não resolve (NXDOMAIN) -> vulnerável.
     Serviço com 'fingerprint': busca o corpo HTTP e casa a assinatura de
     "recurso não reivindicado".

Só rode contra domínios que você é dono ou tem autorização para testar.
"""

from __future__ import annotations

import httpx

from ..models import CollectionResult, Kind, Record
from .http import DEFAULT_MAX_BYTES, _fetch_limited

try:
    import dns.asyncresolver
    import dns.resolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


# nxdomain=True  -> vulnerável quando o alvo do CNAME não resolve
# fingerprint    -> string que o serviço serve quando o recurso não existe
FINGERPRINTS = [
    {"service": "GitHub Pages", "cnames": ["github.io"], "fingerprint": "There isn't a GitHub Pages site here.", "nxdomain": False},
    {"service": "AWS S3", "cnames": ["amazonaws.com"], "fingerprint": "NoSuchBucket", "nxdomain": False},
    {"service": "Heroku", "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"], "fingerprint": "No such app", "nxdomain": False},
    {"service": "Shopify", "cnames": ["myshopify.com"], "fingerprint": "Sorry, this shop is currently unavailable", "nxdomain": False},
    {"service": "Fastly", "cnames": ["fastly.net"], "fingerprint": "Fastly error: unknown domain", "nxdomain": False},
    {"service": "Pantheon", "cnames": ["pantheonsite.io"], "fingerprint": "The gods are wise, but do not know of the site which you seek", "nxdomain": False},
    {"service": "Tumblr", "cnames": ["domains.tumblr.com"], "fingerprint": "Whatever you were looking for doesn't currently exist at this address", "nxdomain": False},
    {"service": "WordPress", "cnames": ["wordpress.com"], "fingerprint": "Do you want to register", "nxdomain": False},
    {"service": "Ghost", "cnames": ["ghost.io"], "fingerprint": "The thing you were looking for is no longer here", "nxdomain": False},
    {"service": "Bitbucket", "cnames": ["bitbucket.io"], "fingerprint": "Repository not found", "nxdomain": False},
    {"service": "Surge.sh", "cnames": ["surge.sh"], "fingerprint": "project not found", "nxdomain": False},
    {"service": "Zendesk", "cnames": ["zendesk.com"], "fingerprint": "Help Center Closed", "nxdomain": False},
    {"service": "Read the Docs", "cnames": ["readthedocs.io"], "fingerprint": "unknown to Read the Docs", "nxdomain": False},
    {"service": "Azure", "cnames": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azure-api.net", "azureedge.net", "azurecontainer.io", "azurefd.net"], "fingerprint": "", "nxdomain": True},
]


def match_service(cname: str) -> dict | None:
    """Casa o alvo de um CNAME contra a base de serviços, respeitando FRONTEIRA
    DE DOMÍNIO (não substring solta): `c == pat` ou `c` termina em `.pat`.

    Assim `foo.github.io` e `github.io` casam, mas `evilgithub.io` e
    `github.io.attacker.com` NÃO — evitando falso positivo por substring.
    """
    c = cname.lower().rstrip(".")
    for fp in FINGERPRINTS:
        for pat in fp["cnames"]:
            pat = pat.lower().rstrip(".")
            if c == pat or c.endswith("." + pat):
                return fp
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
) -> CollectionResult:
    target, resolves, cname_ok = await _cname_target(host, timeout)
    if target is None:
        # sem CNAME (definitivo=ok) ou inconclusivo (ok=False, preserva achado)
        return CollectionResult(records=[], ok=cname_ok)
    fp = match_service(target)
    if not fp:
        # aponta pra um CNAME, mas não é serviço takeover-able conhecido:
        # observação definitiva de "não vulnerável".
        return CollectionResult(records=[], ok=True)

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
        elif fp["fingerprint"].lower() in body.lower():
            reason = "fingerprint de recurso não reivindicado"

    records = []
    if reason:
        records.append(Record(kind=Kind.TAKEOVER, key=host,
                              value=f"{fp['service']} | {target} | {reason}",
                              metadata={"service": fp["service"], "cname": target, "reason": reason}))
    return CollectionResult(records=records, ok=ok)
