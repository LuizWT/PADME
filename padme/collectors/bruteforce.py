"""Bruteforce de subdomínios (ativo, opcional).

Resolve candidatos `<palavra>.<alvo>` de uma wordlist e mantém os que
resolvem em DNS. Complementa os CT logs — acha subdomínios que nunca
apareceram em certificados. Desligado por padrão.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from ..models import Kind, Record

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


async def _resolves(resolver, host: str) -> bool:
    for rtype in ("A", "AAAA"):
        try:
            await resolver.resolve(host, rtype)
            return True
        except Exception:
            continue
    return False


async def collect(target: str, words: list[str], timeout: float,
                  concurrency: int = 50) -> tuple[list[Record], set[str]]:
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
            if await _resolves(resolver, host):
                found.add(host)

    await asyncio.gather(*(check(h) for h in candidates))
    return [Record(Kind.SUBDOMAIN, h) for h in sorted(found)], found
