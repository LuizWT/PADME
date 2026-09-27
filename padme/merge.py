"""Consolidação multi-vantage (sem DB central).

Cada instância PADMÉ (um `source` / ponto de observação) exporta seu estado em
JSON. `merge_exports` junta N exports por (target, kind, key) e mostra, para cada
ativo, DE QUAIS fontes ele foi visto — destacando divergências:

  - presença: ativo visto de algumas fontes, ausente em outras (geo-fencing,
    split-horizon DNS, ou host que só aparece de um ponto — relevante p/ RED);
  - valor: visto de todas as fontes, mas com valor diferente (ex.: banner/served
    content difere conforme a origem).

Puro e testável: recebe listas de linhas de export, devolve a consolidação.
"""

from __future__ import annotations


def merge_exports(exports: list[list[dict]]) -> dict:
    """`exports`: lista de exports (cada um é a lista de linhas do JSON).
    Cada linha deve ter source/target/kind/key/value."""
    by_key: dict[tuple, dict] = {}
    all_sources: set[str] = set()
    for rows in exports:
        for r in rows:
            src = str(r.get("source") or "?")
            all_sources.add(src)
            k = (r.get("target", ""), r.get("kind", ""), r.get("key", ""))
            entry = by_key.setdefault(k, {
                "target": r.get("target", ""), "kind": r.get("kind", ""),
                "key": r.get("key", ""), "by_source": {},
            })
            entry["by_source"][src] = r.get("value", "")

    sources = sorted(all_sources)
    assets: list[dict] = []
    for _, e in sorted(by_key.items()):
        seen = sorted(e["by_source"])
        missing = [s for s in sources if s not in e["by_source"]]
        distinct_values = set(e["by_source"].values())
        divergence = None
        if missing:
            divergence = "presence"       # visto de alguns, ausente em outros
        elif len(distinct_values) > 1:
            divergence = "value"          # visto de todos, mas valores diferem
        assets.append({
            "target": e["target"], "kind": e["kind"], "key": e["key"],
            "sources_seen": seen, "sources_missing": missing,
            "values": dict(e["by_source"]), "divergence": divergence,
        })
    divergences = [a for a in assets if a["divergence"]]
    return {"sources": sources, "asset_count": len(assets),
            "assets": assets, "divergences": divergences}
