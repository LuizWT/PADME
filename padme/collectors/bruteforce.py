"""Bruteforce de subdomínios (ativo, opcional).

Resolve candidatos `<palavra>.<alvo>` de uma wordlist e mantém os que
resolvem em DNS. Complementa os CT logs — acha subdomínios que nunca
apareceram em certificados. Desligado por padrão.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ..models import Kind, Record
from .wildcard import Wildcard

try:
    import dns.asyncresolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

# wordlist mínima embutida, usada quando nenhum arquivo é informado
DEFAULT_WORDS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns", "mx",
    "vpn", "remote", "portal", "api", "admin", "dev", "staging", "stage", "test",
    "qa", "hml", "homolog", "app", "apps", "git", "gitlab", "jenkins", "ci",
    "registry", "docker", "k8s", "blog", "shop", "loja", "cpanel", "whm",
    "autodiscover", "m", "mobile", "beta", "demo", "dashboard", "painel",
    "status", "monitor", "grafana", "kibana", "secure", "login", "auth", "sso",
    "intranet", "extranet", "files", "cdn", "static", "assets", "img", "db",
    "backup", "old", "new", "internal", "corp", "ns3", "gw",
]


def load_words(path: str = "") -> list[str]:
    if path:
        p = Path(path)
        if p.exists():
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            return [w.strip() for w in lines if w.strip() and not w.startswith("#")]
    return DEFAULT_WORDS


async def _resolve_ips(resolver, host: str) -> set[str]:
    ips: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rtype)
        except Exception:
            continue
        ips |= {r.to_text().rstrip(".") for r in answer}
    return ips


async def collect(target: str, words: list[str], timeout: float,
                  concurrency: int = 50,
                  wildcard: Wildcard | None = None) -> tuple[list[Record], set[str]]:
    if not _HAS_DNS:
        return [], set()
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    sem = asyncio.Semaphore(concurrency)
    apex = target.lower().lstrip(".")
    candidates = sorted({f"{w.lower()}.{apex}" for w in words if w.strip()})
    found: set[str] = set()

    async def check(host: str) -> None:
        async with sem:
            ips = await _resolve_ips(resolver, host)
            if not ips:
                return
            # Sob curinga, descarta o que só aponta pro catch-all (host falso);
            # um host real resolve para IP diferente e sobrevive ao filtro.
            if wildcard is not None and wildcard.matches(ips):
                return
            found.add(host)

    await asyncio.gather(*(check(h) for h in candidates))
    return [Record(Kind.SUBDOMAIN, h) for h in sorted(found)], found
