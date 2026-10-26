"""Findings: identidade estável e ciclo de vida dos problemas abertos.

Um *finding* é um problema derivado do ESTADO atual da superfície (takeover,
cert expirando, wildcard de DNS, política de e-mail fraca). Antes ele era
recalculado a cada render, sem identidade nem memória — o painel mostrava o
mesmo problema para sempre e não havia como dizer "já vi" ou "é falso
positivo". Aqui ele ganha:

  - `finding_id` determinístico: hash de (alvo, kind, key[, código]). O mesmo
    problema mantém o mesmo id entre scans (o valor pode mudar — "expira em 6
    dias" → "5 dias" — sem virar outro finding);
  - status: `open` → `acknowledged` (visto, ainda pede correção) ou
    `suppressed` (falso positivo) / `accepted` (risco aceito); `resolved`
    quando some do estado; reabre sozinho (`open`, reopen_count+1) se voltar;
  - prazo (SLA) por severidade, contado desde a (re)abertura.

`suppressed`/`accepted` saem da lista de problemas abertos e não notificam.
`acknowledged` continua aberto e notificando: reconhecer não é resolver.

Só lógica pura (sem SQL nem HTML): o `storage` persiste, o painel e a CLI
mostram. A derivação mora aqui para os três usarem a mesma regra.
"""

from __future__ import annotations

import hashlib

from .evidence import evidence_of
from .mailpolicy import SPF_INCLUDE_UNREGISTERED
from .mailpolicy import findings as mail_findings
from .models import Kind

OPEN, ACKNOWLEDGED, SUPPRESSED, ACCEPTED, RESOLVED = (
    "open", "acknowledged", "suppressed", "accepted", "resolved")
STATUSES = (OPEN, ACKNOWLEDGED, SUPPRESSED, ACCEPTED, RESOLVED)
ACTIVE = frozenset({OPEN, ACKNOWLEDGED})   # pedem ação: contam como problema aberto
MUTED = frozenset({SUPPRESSED, ACCEPTED})  # tratados: fora da lista, não notificam

# ação do analista -> status de destino. `resolved` não é ação: só o scan
# resolve (o problema sumiu do estado). Fechar à mão algo ainda presente seria
# desfeito no próximo ciclo.
ACTIONS = {"ack": ACKNOWLEDGED, "suppress": SUPPRESSED, "accept": ACCEPTED, "reopen": OPEN}

STATUS_LABEL = {
    OPEN: "aberto", ACKNOWLEDGED: "reconhecido", SUPPRESSED: "silenciado",
    ACCEPTED: "risco aceito", RESOLVED: "resolvido",
}

# classe de status do painel -> severidade do finding (chave do SLA)
SEVERITY_OF_CLS = {"s-crit": "critical", "s-serious": "high", "s-warn": "medium"}
DEFAULT_SLA_HOURS = {"critical": 24, "high": 72, "medium": 168}


def finding_id(target: str, kind: str, key: str, code: str = "") -> str:
    """Id estável e curto (16 hex). Separador \\x1f: não aparece em host/key,
    então ('a', 'b|c') e ('a|b', 'c') nunca colidem."""
    raw = "\x1f".join((target, kind, key, code))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _evidence_facts(kind: Kind, key: str, value: str, metadata: dict | None) -> str:
    """Prova normalizada compacta ('tipo — k=v · k=v') p/ o cartão de finding
    agregado, ou '' se não houver. Mesma projeção do webhook/timeline (evidence_of)."""
    ev = evidence_of(kind, key, value, metadata)
    if not ev:
        return ""
    typ = ev.get("type", "")
    facts = " · ".join(f"{k}={v}" for k, v in ev.items() if k != "type")
    return f"{typ} — {facts}" if facts else typ


def _item(target, kind: Kind, key, code, rank, cls, sev, label, who, det, evidence) -> dict:
    return {"id": finding_id(target, kind.value, key, code), "src_kind": kind.value,
            "src_key": key, "severity": SEVERITY_OF_CLS.get(cls, "medium"),
            "rank": rank, "cls": cls, "sev": sev, "kind": label, "who": who,
            "det": det, "tgt": target, "evidence": evidence}


def derive(target: str, kinds: dict) -> list[dict]:
    """Findings do estado atual de UM alvo. `kinds`: {kind: [linha do state]},
    com linhas {key, value, metadata}. Ordem: mais grave primeiro."""
    out: list[dict] = []
    for it in kinds.get("takeover", []):
        out.append(_item(target, Kind.TAKEOVER, it["key"], "", 4, "s-crit", "crítico",
                         "TAKEOVER", it["key"], it["value"],
                         _evidence_facts(Kind.TAKEOVER, it["key"], it["value"], it.get("metadata"))))
    for it in kinds.get("cert_expiry", []):
        expired = "EXPIRAD" in (it["value"] or "").upper()
        out.append(_item(target, Kind.CERT_EXPIRY, it["key"], "",
                         4 if expired else 3, "s-crit" if expired else "s-serious",
                         "expirado" if expired else "expira", "CERT", it["key"], it["value"],
                         _evidence_facts(Kind.CERT_EXPIRY, it["key"], it["value"], it.get("metadata"))))
    for it in kinds.get("wildcard", []):
        out.append(_item(target, Kind.WILDCARD, it["key"], "", 2, "s-warn", "atenção",
                         "WILDCARD", it["key"], f"catch-all {it['value']}",
                         _evidence_facts(Kind.WILDCARD, it["key"], it["value"], it.get("metadata"))))
    for it in kinds.get("mailsec", []):  # política de e-mail publicada, mas fraca
        md = it.get("metadata") or {}
        for f in mail_findings(it["key"], it["value"], md):
            crit = f.code == SPF_INCLUDE_UNREGISTERED  # takeover de e-mail = crítico
            out.append(_item(target, Kind.MAILSEC, it["key"], f.code,
                             4 if crit else (3 if f.high else 2),
                             "s-crit" if crit else ("s-serious" if f.high else "s-warn"),
                             "crítico" if crit else ("fraco" if f.high else "atenção"),
                             "E-MAIL", it["key"].split("|", 1)[0], f.label,
                             _evidence_facts(Kind.MAILSEC, it["key"], it["value"], md)))
    out.sort(key=lambda p: (-p["rank"], p["who"]))
    return out


def ids_for_record(target: str, kind: str, key: str, value, metadata: dict | None) -> list[str]:
    """Ids dos findings que UM record gera (vazio se não gera nenhum) — liga um
    evento ao(s) finding(s) dele sem consultar o estado inteiro."""
    row = {"key": key, "value": value or "", "metadata": metadata or {}}
    return [f["id"] for f in derive(target, {kind: [row]})]


def is_muted(target: str, event, statuses: dict[str, str]) -> bool:
    """O evento é de finding(s) TODOS silenciados/aceitos? Então não notifica.
    Um record de e-mail pode gerar vários findings: um código novo (ainda
    aberto) no mesmo record volta a notificar."""
    val = event.old_value if event.event_type.value == "removed" else event.new_value
    ids = ids_for_record(target, event.kind.value, event.key, val, event.metadata)
    return bool(ids) and all(statuses.get(i) in MUTED for i in ids)


def sla_info(row: dict, now: float, sla_hours: dict[str, int]) -> dict | None:
    """Idade e prazo de um finding ATIVO, contados desde a (re)abertura.
    None para status tratado/resolvido ou severidade sem prazo (0 = sem SLA)."""
    if row.get("status") not in ACTIVE:
        return None
    # `is None`, não `or`: timestamp 0 é um valor válido
    opened = row.get("opened_at")
    if opened is None:
        opened = row.get("first_seen")
    if opened is None:
        return None
    age_h = max(0.0, (now - float(opened)) / 3600)
    limit = int(sla_hours.get(row.get("severity", ""), 0) or 0)
    if limit <= 0:
        return {"age_h": age_h, "limit_h": 0, "left_h": None, "breached": False}
    left = limit - age_h
    return {"age_h": age_h, "limit_h": limit, "left_h": left, "breached": left < 0}


def human_hours(h: float) -> str:
    """12.4 -> '12h', 50 -> '2d 2h', 0.3 -> '<1h'."""
    h = abs(h)
    if h < 1:
        return "<1h"
    if h < 48:
        return f"{int(h)}h"
    d, r = divmod(int(h), 24)
    return f"{d}d {r}h" if r else f"{d}d"
