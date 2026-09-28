"""Contexto de ativo (por configuração, sem tabela `assets`).

O risk engine precisa saber MAIS que "kind + tipo de evento" para classificar bem:
uma porta 3389 nova num ativo *internet-facing/crítico* é pior que a mesma porta
num host interno de teste. Este módulo resolve, de forma determinística e a partir
do `config.yaml`, o contexto de um host/alvo:

    criticality  (low | medium | high | critical | unknown)
    environment  (production | staging | ... | unknown)
    exposure     (internet | internal | unknown)
    owner        (livre)
    expected_ports / forbidden_ports  (política de exposição — §11 do roadmap)

Sem entidade persistente: é só leitura de config casada por `match` (exato ou
glob fnmatch) contra o host do evento e o alvo. Regra mais específica vence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch


@dataclass(frozen=True)
class AssetContext:
    match: str = ""
    criticality: str = "unknown"
    environment: str = "unknown"
    exposure: str = "unknown"        # internet | internal | unknown
    owner: str = ""
    expected_ports: tuple[int, ...] = ()
    forbidden_ports: tuple[int, ...] = ()

    def as_dict(self) -> dict:
        """Forma compacta p/ carimbar no metadata do evento (só o que tem valor)."""
        out: dict = {}
        if self.criticality != "unknown":
            out["criticality"] = self.criticality
        if self.environment != "unknown":
            out["environment"] = self.environment
        if self.exposure != "unknown":
            out["exposure"] = self.exposure
        if self.owner:
            out["owner"] = self.owner
        if self.expected_ports:
            out["expected_ports"] = list(self.expected_ports)
        if self.forbidden_ports:
            out["forbidden_ports"] = list(self.forbidden_ports)
        if out:
            out["match"] = self.match
        return out


@dataclass
class ContextConfig:
    assets: list[AssetContext] = field(default_factory=list)


def _matches(pattern: str, host: str, target: str) -> bool:
    p = pattern.lower().strip()
    if not p:
        return False
    for cand in (host, target):
        c = (cand or "").lower()
        if c and (c == p or fnmatch(c, p)):
            return True
    return False


def resolve(host: str, target: str, rules: list[AssetContext]) -> AssetContext | None:
    """Contexto do host/alvo. Se várias regras casam, a MAIS ESPECÍFICA vence
    (match exato > glob; empate desempata pelo `match` mais longo). Determinístico."""
    hits = [r for r in rules if _matches(r.match, host, target)]
    if not hits:
        return None

    def specificity(r: AssetContext) -> tuple[int, int]:
        exact = 1 if r.match.lower() in ((host or "").lower(), (target or "").lower()) else 0
        return (exact, len(r.match))

    return max(hits, key=specificity)
