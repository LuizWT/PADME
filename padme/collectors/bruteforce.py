"""Bruteforce de subdomínios (ativo, opcional).

Resolve candidatos `<palavra>.<alvo>` de uma wordlist e mantém os que
resolvem em DNS. Complementa os CT logs — acha subdomínios que nunca
apareceram em certificados. Desligado por padrão.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from ..models import CollectionResult, Kind, Record
from .wildcard import Wildcard

# label DNS válido: 1–63 chars, alfanumérico + hífen (sem começar/terminar em -)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

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


def _valid_word(raw: str) -> str | None:
    """Normaliza e valida um item da wordlist. Retorna None se inválido/comentário."""
    w = raw.strip().lower().rstrip(".")
    if not w or w.startswith("#") or "*" in w:
        return None
    # aceita labels compostos (ex.: 'dev.api'); valida cada label
    if all(_LABEL_RE.match(lb) for lb in w.split(".")):
        return w
    return None


def _normalize(lines: list[str]) -> list[str]:
    """Limpa (espaços, vazias, comentários, inválidos) e deduplica preservando ordem."""
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        w = _valid_word(line)
        if w and w not in seen:
            seen.add(w)
            out.append(w)
    return out


def load_words(path: str = "") -> list[str]:
    """Carrega a wordlist. Sem caminho -> lista embutida. Caminho CONFIGURADO mas
    inexistente -> erro claro (não cai silenciosamente pro default, o que
    mascararia um erro de configuração)."""
    if not path:
        return _normalize(DEFAULT_WORDS)
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"wordlist configurada não encontrada: {path}")
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    return _normalize(lines)


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
                  wildcard: Wildcard | None = None, pace=None) -> CollectionResult:
    if not _HAS_DNS:
        return CollectionResult(records=[], ok=False)
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    sem = asyncio.Semaphore(concurrency)
    apex = target.lower().lstrip(".")
    candidates = sorted({f"{w.lower()}.{apex}" for w in words if w.strip()})
    found: set[str] = set()

    async def check(host: str) -> None:
        async with sem:
            if pace is not None:  # rate-limit: as consultas chegam ao NS do alvo
                await pace(host)
            ips = await _resolve_ips(resolver, host)
            if not ips:
                return
            # Sob curinga, descarta o que só aponta pro catch-all (host falso);
            # um host real resolve para IP diferente e sobrevive ao filtro.
            if wildcard is not None and wildcard.matches(ips):
                return
            found.add(host)

    await asyncio.gather(*(check(h) for h in candidates))
    records = [Record(Kind.SUBDOMAIN, h) for h in sorted(found)]
    # bruteforce é SUPLEMENTAR: enriquece a descoberta, mas não é autoritativo
    # sobre o escopo de subdomínio (só cobre a wordlist). Quem decide se o
    # escopo foi observado é a descoberta por CT (subdomains.collect).
    return CollectionResult(records=records, ok=True, hosts=found)
