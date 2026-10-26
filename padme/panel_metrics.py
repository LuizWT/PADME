"""Métricas do painel: a lógica de DADOS por trás dos cartões, sem HTML.

Problemas abertos, priorização da timeline, cobertura de explicabilidade e
confiabilidade dos collectors (§27). Separado do `webpanel` (que só renderiza e
serve) para ser testável e legível sozinho.
"""

from __future__ import annotations

from .evidence import evidence_of
from .findings import (
    ACTIVE,
    MUTED,
    OPEN,
    _evidence_facts,  # noqa: F401 — reexport (a derivação mora em findings)
    derive,
)
from .risk import Level, assess


def _prioritize_events(events: list):
    """Ordena a timeline por RELEVÂNCIA (severidade do assess) e depois por
    recência — o que importa (takeover, exposição crítica) fica no topo em vez de
    soterrado sob ruído (mudança de DNS etc.). Cada linha mostra o timestamp, então
    a cronologia continua legível. Devolve [(evento, risco)] já avaliado (§15.4)."""
    scored = [(e, assess(e)) for e in events]
    scored.sort(key=lambda er: (int(er[1].level), er[0].detected_at or ""), reverse=True)
    return scored


def _collect_problems(by_target: dict, meta: dict,
                      statuses: dict[str, dict] | None = None,
                      include_muted: bool = False) -> list[dict]:
    """Problemas abertos do estado atual, mais grave primeiro.

    `statuses`: {finding_id: linha da tabela findings} — anota status/idade em
    cada problema e tira da lista os silenciados/aceitos (vão para "tratados"
    com `include_muted=True`). Sem `statuses` (banco antigo/teste), tudo conta
    como aberto, como antes do lifecycle."""
    statuses = statuses or {}
    prob: list[dict] = []
    for target, kinds in by_target.items():
        for f in derive(target, kinds):
            row = statuses.get(f["id"]) or {}
            st = row.get("status") or OPEN
            if st not in ACTIVE and st not in MUTED:
                st = OPEN  # 'resolved' no banco mas presente no estado: o scan reabre
            if (st in MUTED) != include_muted:
                continue
            prob.append({**f, "status": st, "row": row})
    if not include_muted:
        # coleta parcial por alvo (não é da superfície, mas é um problema operacional;
        # transitório, então sem lifecycle — some sozinho na próxima coleta completa)
        for target, m in meta.items():
            if m and m.get("last_partial"):
                n = m.get("last_error_count") or "?"
                prob.append({"rank": 2, "cls": "s-warn", "sev": "atenção", "kind": "COLETA",
                             "who": target, "det": f"coleta parcial — {n} erro(s) de collector",
                             "tgt": target, "status": OPEN, "row": {}})
    prob.sort(key=lambda p: (-p["rank"], p["tgt"], p["who"]))
    return prob


def _explainability(events_by_target: dict) -> dict | None:
    """Cobertura de explicabilidade (§27): dos eventos HIGH/CRITICAL recentes,
    quantos trazem os TRÊS pilares juntos — razão (reason code do risco),
    proveniência (`_collector`/`_source`) e evidência normalizada. Mede se o
    alerta grave é justificável na hora, sem o analista caçar contexto. Um
    número baixo aponta pipeline que grita sem sustentar a conclusão.

    Só considera o que já está carregado (eventos recentes) — sem query nova."""
    high = explained = 0
    gaps = {"razão": 0, "proveniência": 0, "evidência": 0}
    for evs in events_by_target.values():
        for e in evs:
            risk = assess(e)
            if int(risk.level) < int(Level.HIGH):
                continue
            high += 1
            val = e.new_value if e.event_type.value != "removed" else e.old_value
            md = e.metadata or {}
            has_reason = bool(risk.reason_labels())
            has_prov = bool(md.get("_collector") or md.get("_source"))
            has_ev = evidence_of(e.kind, e.key, val, md) is not None
            if has_reason and has_prov and has_ev:
                explained += 1
            else:
                if not has_reason:
                    gaps["razão"] += 1
                if not has_prov:
                    gaps["proveniência"] += 1
                if not has_ev:
                    gaps["evidência"] += 1
    if high == 0:
        return None
    missing = sorted((k for k, v in gaps.items() if v), key=lambda k: -gaps[k])
    return {"high": high, "explained": explained,
            "pct": round(100 * explained / high), "missing": missing}


_HEALTH_RANK = {"ok": 0, "partial": 1, "error": 2}


def _collector_reliability(meta: dict) -> dict | None:
    """Confiabilidade dos collectors (§27) consolidada entre os alvos. Cada
    (alvo, collector) do último scan conta como uma observação; a cobertura é a
    fração `ok`. Aponta os collectors degradados (o pior status visto) — um
    collector em erro significa cegueira parcial da superfície, não 'tudo limpo'.
    Reusa `collectors_health` já gravado por scan; sem query nova."""
    total = ok = 0
    degraded: dict[str, str] = {}  # collector -> pior status visto
    for m in meta.values():
        ch = (m or {}).get("collectors_health") or {}
        for name, v in ch.items():
            st = (v or {}).get("status")
            if st not in _HEALTH_RANK:
                continue
            total += 1
            if st == "ok":
                ok += 1
            elif _HEALTH_RANK[st] > _HEALTH_RANK.get(degraded.get(name, "ok"), 0):
                degraded[name] = st
    if total == 0:
        return None
    worst = sorted(degraded, key=lambda n: -_HEALTH_RANK[degraded[n]])
    has_error = any(s == "error" for s in degraded.values())
    return {"total": total, "ok": ok, "pct": round(100 * ok / total),
            "degraded": worst, "has_error": has_error}


def _collector_table(meta: dict) -> list[dict]:
    """Saúde POR collector consolidada entre os alvos (linha da tabela da visão
    geral): quantos alvos o collector cobriu ok no último scan e o pior status
    visto. Ordena o degradado primeiro — é o que pede atenção."""
    agg: dict[str, dict] = {}
    for m in meta.values():
        for name, v in ((m or {}).get("collectors_health") or {}).items():
            st = (v or {}).get("status")
            if st not in _HEALTH_RANK:
                continue
            row = agg.setdefault(name, {"name": name, "ok": 0, "total": 0, "worst": "ok"})
            row["total"] += 1
            if st == "ok":
                row["ok"] += 1
            if _HEALTH_RANK[st] > _HEALTH_RANK[row["worst"]]:
                row["worst"] = st
    return sorted(agg.values(), key=lambda r: (-_HEALTH_RANK[r["worst"]], r["name"]))
