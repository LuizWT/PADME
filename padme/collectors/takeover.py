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

from ..models import Kind, Record

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
    """Casa o alvo de um CNAME contra a base de serviços."""
    c = cname.lower().rstrip(".")
    for fp in FINGERPRINTS:
        if any(pat in c for pat in fp["cnames"]):
            return fp
    return None


async def _cname_target(host: str, timeout: float) -> tuple[str | None, bool]:
    """Retorna (alvo do CNAME | None, alvo_resolve)."""
    if not _HAS_DNS:
        return None, True
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    try:
        ans = await resolver.resolve(host, "CNAME")
    except Exception:
        return None, True  # sem CNAME -> não é candidato
    target = str(ans[0].target).rstrip(".")
    try:
        await resolver.resolve(target, "A")
        return target, True
    except dns.resolver.NXDOMAIN:
        return target, False
    except Exception:
        return target, True  # inconclusivo -> não crava dangling


async def _body(client: httpx.AsyncClient, host: str, cache: dict[str, str] | None = None) -> str:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        if cache is not None and url in cache:  # reaproveita o GET do collector HTTP
            return cache[url]
        try:
            r = await client.get(url, follow_redirects=True)
            return r.text or ""
        except Exception:
            continue
    return ""


async def collect_host(
    host: str, client: httpx.AsyncClient, timeout: float, cache: dict[str, str] | None = None
) -> list[Record]:
    target, resolves = await _cname_target(host, timeout)
    if not target:
        return []
    fp = match_service(target)
    if not fp:
        return []

    reason = ""
    if fp["nxdomain"]:
        if not resolves:
            reason = "CNAME dangling (NXDOMAIN)"
    elif fp["fingerprint"]:
        body = await _body(client, host, cache)
        if fp["fingerprint"].lower() in body.lower():
            reason = "fingerprint de recurso não reivindicado"

    if not reason:
        return []

    value = f"{fp['service']} | {target} | {reason}"
    return [Record(kind=Kind.TAKEOVER, key=host, value=value)]
