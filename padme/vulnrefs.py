"""Referências dos CVEs de um problema de versão (`Kind.VULN`).

Link de cada CVE no OSV e quais destacar num alerta. Puro, sem rede nem
dependências: usado pelo painel, pelos canais de notificação e pela CLI, a
partir do metadata que o `padme.osv` grava no record (`vulns`, pior primeiro).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

OSV_VULN_URL = "https://osv.dev/vulnerability/"


def osv_url(vuln_id: str) -> str:
    """Página do CVE (ou aviso da distro) no OSV."""
    return OSV_VULN_URL + quote(str(vuln_id), safe="-._:")


def label(vuln: dict[str, Any]) -> str:
    """'high 8.1' / 'medium' / 'unknown': severidade e nota, quando houver."""
    sev = str(vuln.get("severity") or "unknown")
    score = vuln.get("score")
    return f"{sev} {float(score):.1f}" if isinstance(score, (int, float)) else sev


def refs(metadata: dict[str, Any] | None,
         changes: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """CVEs do problema, pior primeiro, cada um com `url` e `label`.

    Com `changes` (o diff de um CHANGED), só os que entraram agora, que são o
    motivo do alerta. Se nenhum entrou (a lista só diminuiu), todos."""
    md = metadata or {}
    vulns = [v for v in md.get("vulns") or [] if isinstance(v, dict) and v.get("id")]
    ch = (changes or {}).get("cves")
    if isinstance(ch, dict):
        new = set(ch.get("new") or []) - set(ch.get("old") or [])
        if new:
            vulns = [v for v in vulns if v["id"] in new]
    return [{"id": str(v["id"]), "severity": v.get("severity"), "score": v.get("score"),
             "fixed": v.get("fixed"), "url": osv_url(v["id"]), "label": label(v)}
            for v in vulns]
