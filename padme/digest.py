"""Resumo periódico (digest): o que aconteceu no período, num relance.

O alerta em tempo real só fala quando algo MUDA. Silêncio pode significar
"nada mudou" ou "o monitor morreu" — o heartbeat cobre a segunda (para um
serviço externo), mas quem opera quer ler, de vez em quando, um resumo humano:
mudanças do período, problemas abertos, prazos estourados e a saúde da coleta.

  - agenda: diária ou semanal, numa hora local (`digest.hour`);
  - período: desde o último resumo enviado (gravado no banco — reiniciar o
    monitor não duplica nem pula), com teto de 31 dias;
  - primeiro uso: só marca o início, sem enviar na hora (o primeiro resumo
    sai no próximo horário agendado); `padme digest` gera um na hora;
  - conteúdo: as mesmas regras do painel — mudanças sem DNS (como a
    tendência), findings pelo ciclo de vida (silenciado/aceito não aparece
    como problema), destaques só HIGH+ e fora de finding silenciado.

`build` produz dados (JSON-serializáveis, vão no webhook); `render` produz o
texto que os canais de chat/e-mail enviam.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from datetime import datetime, timedelta

from .findings import ACTIVE, MUTED, RESOLVED, is_muted, sla_info
from .models import Kind
from .risk import Level, assess

log = logging.getLogger("padme")

WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
SCHEDULES = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
_META_KEY = "digest.last_sent_at"
_MAX_PERIOD = 31 * 86400
_EVENTS_CAP = 5000
_HIGHLIGHTS = 5
_SEV_PT = {"critical": "crítico", "high": "alto", "medium": "médio"}
_LEVEL_PT = {Level.CRITICAL: "crítico", Level.HIGH: "alto"}


# ── agenda ───────────────────────────────────────────────────────────────────
def last_slot(now: datetime, schedule: str, hour: int, weekday: str) -> datetime:
    """Horário agendado mais recente <= now (hora local, sem fuso)."""
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if schedule == "weekly":
        slot -= timedelta(days=(now.weekday() - WEEKDAYS.index(weekday)) % 7)
        if slot > now:
            slot -= timedelta(days=7)
    elif slot > now:
        slot -= timedelta(days=1)
    return slot


def next_slot(now: datetime, schedule: str, hour: int, weekday: str) -> datetime:
    return last_slot(now, schedule, hour, weekday) + SCHEDULES[schedule]


def seconds_until_next(cfg, now: datetime | None = None) -> float | None:
    """Segundos até o próximo resumo (o monitor acorda para ele); None se off."""
    d = cfg.digest
    if not d.enabled:
        return None
    now = now or datetime.now()
    return max(0.0, (next_slot(now, d.schedule, d.hour, d.weekday) - now).total_seconds())


def due(cfg, storage, now: datetime | None = None) -> tuple[bool, float | None]:
    """(está na hora?, início do período). No primeiro uso grava `agora` como
    início e responde False: o primeiro resumo sai no próximo horário."""
    d = cfg.digest
    if not d.enabled:
        return False, None
    now = now or datetime.now()
    raw = storage.get_meta(_META_KEY)
    if raw is None:
        storage.set_meta(_META_KEY, str(now.timestamp()))
        log.info("Resumo %s agendado: o primeiro sai em %s.",
                 "diário" if d.schedule == "daily" else "semanal",
                 next_slot(now, d.schedule, d.hour, d.weekday).strftime("%d/%m %H:%M"))
        return False, None
    try:
        last = float(raw)
    except ValueError:
        last = now.timestamp() - SCHEDULES[d.schedule].total_seconds()
    slot = last_slot(now, d.schedule, d.hour, d.weekday).timestamp()
    if last >= slot:
        return False, None
    return True, max(last, now.timestamp() - _MAX_PERIOD)


# ── dados ────────────────────────────────────────────────────────────────────
def _iso(ts) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts)).isoformat(timespec="minutes")


def build(cfg, storage, start: float, end: float | None = None) -> dict:
    """Dados do resumo do período [start, end] para todos os alvos do config."""
    end = time.time() if end is None else end
    stale_after = 2 * cfg.interval_seconds + 600   # mesmo limite do `padme health`
    targets = []
    for t in cfg.targets:
        evs = [e for e in storage.query_events(targets=[t], since_ts=start, cap=_EVENTS_CAP)
               if e.kind != Kind.DNS]   # rotação de IP de CDN não é a superfície mudando
        counts = Counter(e.event_type.value for e in evs)
        rows = storage.list_findings(target=t)
        statuses = {r["finding_id"]: r["status"] for r in rows}
        scored = [(assess(e), e) for e in evs if not is_muted(t, e, statuses)]
        hi = sorted((x for x in scored if x[0].level >= Level.HIGH),
                    key=lambda x: (-int(x[0].level), x[1].detected_at or ""))[:_HIGHLIGHTS]
        active = [r for r in rows if r["status"] in ACTIVE]
        late = sum(1 for r in active
                   if (i := sla_info(r, end, cfg.findings.sla_hours)) and i["breached"])
        meta = storage.target_meta(t) or {}
        last_scan = meta.get("last_scan_at")
        targets.append({
            "target": t,
            "changes": {k: counts.get(k, 0) for k in ("added", "changed", "removed")},
            "open": len(active),
            "open_by_severity": dict(Counter(r["severity"] for r in active)),
            "sla_breached": late,
            "new": [r["title"] for r in active if (r["opened_at"] or 0) >= start],
            "resolved": [r["title"] for r in rows
                         if r["status"] == RESOLVED and (r["resolved_at"] or 0) >= start],
            "treated": sum(1 for r in rows if r["status"] in MUTED),
            "highlights": [{"level": _LEVEL_PT.get(a.level, a.level.name.lower()),
                            "kind": e.kind.value, "key": e.key,
                            "value": e.new_value if e.event_type.value != "removed" else e.old_value,
                            "type": e.event_type.value} for a, e in hi],
            "last_scan_at": _iso(last_scan),
            "stale": last_scan is None or end - float(last_scan) > stale_after,
            "partial": bool(meta.get("last_partial")),
            "degraded": sorted(n for n, v in (meta.get("collectors_health") or {}).items()
                               if (v or {}).get("status") in ("partial", "error")),
        })
    total_changes = {k: sum(t["changes"][k] for t in targets) for k in ("added", "changed", "removed")}
    sev = Counter()
    for t in targets:
        sev.update(t["open_by_severity"])
    return {
        "schedule": cfg.digest.schedule,
        "period_start": _iso(start), "period_end": _iso(end),
        "targets": targets,
        "totals": {
            "targets": len(targets),
            "open": sum(t["open"] for t in targets),
            "open_by_severity": dict(sev),
            "sla_breached": sum(t["sla_breached"] for t in targets),
            "changes": total_changes,
            "complete": sum(1 for t in targets if not t["partial"] and not t["stale"]),
        },
    }


def is_quiet(data: dict) -> bool:
    """Nada a contar: sem mudança, sem problema aberto e com a coleta em dia."""
    return all(
        not any(t["changes"].values()) and not t["open"] and not t["resolved"]
        and not t["stale"] and not t["partial"] and not t["degraded"]
        for t in data["targets"])


# ── texto ────────────────────────────────────────────────────────────────────
def _sev_text(by_sev: dict) -> str:
    parts = [f"{by_sev[s]} {_SEV_PT[s]}" for s in ("critical", "high", "medium") if by_sev.get(s)]
    return ", ".join(parts)


def _chg(c: dict) -> str:
    return f"+{c['added']} · ~{c['changed']} · −{c['removed']}"


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    return datetime.fromisoformat(iso).strftime("%d/%m %H:%M")


def render(data: dict) -> tuple[str, str]:
    """(título, texto) do resumo — texto puro, o mesmo para todos os canais."""
    tot = data["totals"]
    kind = "diário" if data["schedule"] == "daily" else "semanal"
    if tot["open"]:
        headline = f"{tot['open']} problema(s) aberto(s)"
    elif is_quiet(data):
        headline = "nada mudou"
    else:
        headline = "sem problemas abertos"
    title = f"Resumo {kind} · {headline}"
    lines = [f"Período: {_fmt_time(data['period_start'])} → {_fmt_time(data['period_end'])}", ""]
    summary = f"{tot['targets']} alvo(s) · {tot['open']} problema(s) aberto(s)"
    if tot["open"]:
        summary += f": {_sev_text(tot['open_by_severity'])}"
    if tot["sla_breached"]:
        summary += f" · {tot['sla_breached']} com prazo estourado"
    lines += [summary,
              f"Mudanças (sem DNS): {_chg(tot['changes'])}",
              f"Coleta: {tot['complete']} de {tot['targets']} alvo(s) completos e em dia"]
    quiet: list[str] = []
    for t in data["targets"]:
        nothing = (not any(t["changes"].values()) and not t["open"] and not t["resolved"]
                   and not t["stale"] and not t["partial"] and not t["degraded"])
        if nothing:
            quiet.append(t["target"])
            continue
        lines += ["", t["target"]]
        if t["open"]:
            row = f"  abertos: {t['open']} ({_sev_text(t['open_by_severity'])})"
            if t["sla_breached"]:
                row += f" · prazo estourado: {t['sla_breached']}"
            lines.append(row)
        lines += [f"  novo: {x}" for x in t["new"]]
        lines += [f"  resolvido: {x}" for x in t["resolved"]]
        if any(t["changes"].values()):
            lines.append(f"  mudanças: {_chg(t['changes'])}")
        for h in t["highlights"]:
            lines.append(f"  [{h['level']}] {h['kind']} {h['key']} {h['value'] or ''}".rstrip())
        if t["stale"]:
            lines.append(f"  ATENÇÃO: sem scan recente (último: {_fmt_time(t['last_scan_at'])})")
        if t["partial"] or t["degraded"]:
            bits = ["coleta parcial"] if t["partial"] else []
            if t["degraded"]:
                bits.append("degradado: " + ", ".join(t["degraded"]))
            lines.append("  " + " · ".join(bits))
        if t["treated"]:
            lines.append(f"  tratados (falso positivo/risco aceito): {t['treated']}")
    if quiet:
        lines += ["", "Sem novidade: " + ", ".join(quiet)]
    return title, "\n".join(lines)


# ── envio ────────────────────────────────────────────────────────────────────
async def send(cfg, storage, notifier, start: float, now: float | None = None,
               force: bool = False) -> list | None:
    """Monta e envia o resumo pelos canais escolhidos. Marca o envio se pelo
    menos um canal entregou (ou se foi pulado por estar quieto). Devolve os
    resultados por canal, ou None se não enviou nada."""
    now = time.time() if now is None else now
    data = build(cfg, storage, start, now)
    if not force and not cfg.digest.send_if_quiet and is_quiet(data):
        storage.set_meta(_META_KEY, str(now))
        log.info("Resumo: nada a contar no período (send_if_quiet: false) — pulado.")
        return None
    title, text = render(data)
    results = await notifier.digest(title, text, data, channels=cfg.digest.channels or None)
    if not results:
        # nenhum canal ativo casa com digest.channels: marca mesmo assim, senão o
        # aviso se repetiria a cada ciclo até o próximo horário
        storage.set_meta(_META_KEY, str(now))
        log.warning("Resumo: nenhum canal ativo para receber (confira digest.channels "
                    "e o enabled de cada canal).")
        return results
    if any(r.ok for r in results):
        storage.set_meta(_META_KEY, str(now))
    failed = [r.channel for r in results if not r.ok]
    if failed:
        log.warning("Resumo: falhou em %s (tenta de novo no próximo ciclo se nenhum entregou).",
                    ", ".join(failed))
    else:
        log.info("Resumo enviado a %d canal(is).", len(results))
    return results


async def maybe_send(cfg, storage, notifier) -> list | None:
    """Chamado pelo monitor depois de cada ciclo e quando acorda para o horário
    do resumo. Barato quando não é a hora (só lê um valor do banco)."""
    ok, start = due(cfg, storage)
    if not ok or not notifier:
        return None
    return await send(cfg, storage, notifier, start)
