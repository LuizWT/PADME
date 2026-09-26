"""Fase 5 — testes de integração do fluxo inteiro (§56).

fake collectors -> Engine -> Storage -> diff -> NotificationManager.
Cobre os cenários A (baseline), B (mudança real), C (collector falhou preserva),
D (um canal falha, os outros seguem) e E (severidade por canal)."""

import asyncio
import os
import tempfile

from padme.collectors import dns as dnsmod
from padme.collectors import subdomains as submod
from padme.collectors import wildcard as wcmod
from padme.config import CollectorsConfig, Config
from padme.engine import Engine
from padme.levels import Level
from padme.models import CollectionResult, Kind, Record
from padme.notify import NotificationManager, NotificationResult
from padme.storage import Storage


def _cfg(db):
    return Config(targets=["alvo.com"], db_path=db, scope_confirmed=True,
                  collectors=CollectorsConfig(
                      subdomains=True, bruteforce=False, wildcard=True, dns=True,
                      http=False, tls=False, takeover=False, ports=False))


def _patch(monkeypatch, dns_seq):
    async def fake_sub(target, client):
        return CollectionResult(records=[], ok=True, hosts={target})

    async def fake_wc(apex, timeout, probes):
        return wcmod.Wildcard(active=False)

    it = iter(dns_seq)

    async def fake_dns(host, timeout):
        return next(it)

    monkeypatch.setattr(submod, "collect", fake_sub)
    monkeypatch.setattr(wcmod, "detect", fake_wc)
    monkeypatch.setattr(dnsmod, "collect_host", fake_dns)


def test_engine_baseline_mudanca_e_preservacao(monkeypatch):
    """Cenários A + B + C + remoção real, ponta a ponta pelo Engine."""
    rec = Record(Kind.DNS, "alvo.com|A|1.2.3.4", "1.2.3.4")
    _patch(monkeypatch, [
        CollectionResult([rec], ok=True),   # scan1: baseline
        CollectionResult([], ok=False),      # scan2: DNS falhou -> preserva
        CollectionResult([], ok=True),       # scan3: DNS ok e vazio -> REMOVED real
    ])
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    eng = Engine(_cfg(db), s)

    # A) baseline: estado gravado, zero eventos
    e1 = eng.apply(asyncio.run(eng.scan_target("alvo.com")))
    assert e1 == [] and len(s.all_state(["alvo.com"])) == 1

    # C) coleta de DNS falhou (escopo não observado) -> preserva, sem REMOVED falso
    e2 = eng.apply(asyncio.run(eng.scan_target("alvo.com")))
    assert e2 == [] and len(s.all_state(["alvo.com"])) == 1

    # remoção real: DNS observado e o registro sumiu de fato
    e3 = eng.apply(asyncio.run(eng.scan_target("alvo.com")))
    assert [x.event_type.value for x in e3] == ["removed"]
    assert s.all_state(["alvo.com"]) == []
    s.close(); os.remove(db)


def test_engine_mudanca_real_added(monkeypatch):
    """Cenário B isolado: baseline com 1, depois 2 -> exatamente 1 ADDED."""
    r1 = Record(Kind.DNS, "alvo.com|A|1.1.1.1", "1.1.1.1")
    r2 = Record(Kind.DNS, "alvo.com|A|2.2.2.2", "2.2.2.2")
    _patch(monkeypatch, [
        CollectionResult([r1], ok=True),
        CollectionResult([r1, r2], ok=True),
    ])
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    eng = Engine(_cfg(db), s)
    eng.apply(asyncio.run(eng.scan_target("alvo.com")))          # baseline
    evs = eng.apply(asyncio.run(eng.scan_target("alvo.com")))    # +1
    assert [e.event_type.value for e in evs] == ["added"]
    assert evs[0].key == "alvo.com|A|2.2.2.2"
    s.close(); os.remove(db)


# ── D/E: eventos reais do storage -> despacho por canal ─────────────────────
class _Fake:
    def __init__(self, name, level, boom=False):
        self.name = name
        self.level = level
        self._boom = boom
        self.received = None

    @property
    def configured(self):
        return True

    async def notify_events(self, target, events):
        if self._boom:
            raise RuntimeError("canal fora do ar")
        self.received = list(events)
        return NotificationResult(self.name, ok=True, attempts=1, status=204)

    async def announce(self, msg):
        return NotificationResult(self.name, ok=True, attempts=1)


def test_dispatch_por_canal_e_isolamento():
    """Cenário D + E: níveis por canal e um canal com falha não derruba os outros."""
    s_db = tempfile.mktemp(suffix=".db")
    s = Storage(s_db)
    s.apply_scan("alvo.com", [])  # baseline
    evs = s.apply_scan(
        "alvo.com",
        [Record(Kind.TAKEOVER, "a.alvo.com", "GitHub Pages | ..."),  # CRITICAL
         Record(Kind.DNS, "alvo.com|A|1.2.3.4", "1.2.3.4")],          # DEBUG
        observed_scopes={("takeover", "a.alvo.com"), ("dns", "alvo.com")},
    )
    s.close(); os.remove(s_db)
    assert len(evs) == 2

    tg = _Fake("telegram", Level.HIGH)      # só takeover (critical) passa
    dc = _Fake("discord", Level.DEBUG)      # tudo passa
    em = _Fake("email", Level.DEBUG, boom=True)  # estoura
    results = asyncio.run(NotificationManager([tg, dc, em]).dispatch("alvo.com", evs))

    by = {r.channel: r for r in results}
    assert len(tg.received) == 1            # E: telegram(high) recebe só o takeover
    assert len(dc.received) == 2            # E: discord(debug) recebe os dois
    assert by["telegram"].ok and by["discord"].ok
    assert by["email"].ok is False          # D: falha registrada, não propaga
