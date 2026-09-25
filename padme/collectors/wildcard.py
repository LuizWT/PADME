"""Detecção de Wildcard DNS (curinga).

Um apex com curinga (`*.alvo.com`) faz **qualquer** nome resolver — inclusive
`nome-que-nunca-existiu.alvo.com`. Sem tratar isso, a enumeração ativa
(bruteforce) vira uma inundação de subdomínios falsos: cada palavra "resolve",
mas aponta pro mesmo endereço catch-all e não é um host de verdade.

Estratégia:
  1. sondamos N nomes aleatórios sob o apex (quase certamente inexistentes);
  2. se pelo menos 2 resolverem e compartilharem um conjunto de IPs, o apex tem
     curinga, e esses IPs são o "catch-all";
  3. com isso, o bruteforce descarta candidatos que só resolvem para o catch-all
     (host real resolve para um IP **diferente** e sobrevive ao filtro).

Puramente defensivo: qualquer falha (sem dnspython, erro de rede) devolve
`Wildcard(active=False)` — na dúvida, não suprime nada.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass

try:
    import dns.asyncresolver  # type: ignore

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


@dataclass(frozen=True)
class Wildcard:
    """Resultado da sondagem de curinga de um apex."""

    active: bool = False
    ips: frozenset[str] = frozenset()

    def matches(self, ips: set[str] | frozenset[str]) -> bool:
        """True se `ips` (não vazio) cai inteiramente dentro do catch-all — ou
        seja, o host só resolve para os IPs do curinga, então é artefato."""
        if not self.active or not ips:
            return False
        return set(ips).issubset(self.ips)


def _random_label() -> str:
    """Rótulo aleatório improvável de existir (12 hex)."""
    return "padme-wc-" + secrets.token_hex(6)


def classify_probe_ips(probe_ip_sets: list[set[str]]) -> Wildcard:
    """Decide o curinga a partir dos IPs resolvidos de cada sonda.

    Regra: curinga ativo quando >= 2 sondas resolveram e a interseção dos seus
    conjuntos de IPs é não vazia (um catch-all estável). Os IPs do curinga são
    essa interseção — só suprimimos o que bate com o catch-all comum a todas.
    """
    resolved = [s for s in probe_ip_sets if s]
    if len(resolved) < 2:
        return Wildcard(active=False)
    common: set[str] = set(resolved[0])
    for s in resolved[1:]:
        common &= s
    if not common:
        return Wildcard(active=False)
    return Wildcard(active=True, ips=frozenset(common))


async def _resolve_ips(resolver, host: str) -> set[str]:
    ips: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, rtype)
        except Exception:
            continue
        ips |= {r.to_text().rstrip(".") for r in answer}
    return ips


async def detect(apex: str, timeout: float, probes: int = 3) -> Wildcard:
    """Sonda `probes` nomes aleatórios sob o apex e classifica o curinga."""
    if not _HAS_DNS or probes < 2:
        return Wildcard(active=False)
    apex = apex.lower().lstrip(".")
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    hosts = [f"{_random_label()}.{apex}" for _ in range(probes)]
    try:
        ip_sets = await asyncio.gather(*(_resolve_ips(resolver, h) for h in hosts))
    except Exception:  # pragma: no cover - gather não deve propagar aqui
        return Wildcard(active=False)
    return classify_probe_ips(list(ip_sets))
