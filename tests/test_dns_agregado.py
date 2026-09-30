"""DNS agregado por host|tipo (ponto 4): rotação de IP vira UM evento."""

import asyncio
import os
import sqlite3
import tempfile

from padme.collectors import dns as dnsmod
from padme.collectors.dns import dns_record
from padme.engine import _ips_from_dns
from padme.models import Event, EventType, Kind, Record
from padme.notify import email, telegram, webhook
from padme.storage import Storage


class _RR:
    def __init__(self, text):
        self._t = text

    def to_text(self):
        return self._t


def _fake_resolver(table):
    class _Res:
        lifetime = 0

        async def resolve(self, host, rtype):
            if (host, rtype) in table:
                return [_RR(v) for v in table[(host, rtype)]]
            raise dnsmod.dns.resolver.NoAnswer()
    return _Res


def test_collector_agrega_por_tipo(monkeypatch):
    table = {("a.com", "A"): ["2.2.2.2", "1.1.1.1", "1.1.1.1"],
             ("a.com", "MX"): ["10 mx.a.com."]}
    monkeypatch.setattr(dnsmod.dns.asyncresolver, "Resolver", _fake_resolver(table))
    cr = asyncio.run(dnsmod.collect_host("a.com", 5))
    recs = {r.key: r for r in cr.records}
    assert set(recs) == {"a.com|A", "a.com|MX"}
    assert recs["a.com|A"].value == "1.1.1.1, 2.2.2.2"            # ordenado e sem duplicata
    assert recs["a.com|A"].metadata == {"values": ["1.1.1.1", "2.2.2.2"]}
    assert recs["a.com|MX"].value == "10 mx.a.com"


def test_fallback_getaddrinfo_separa_v4_e_v6(monkeypatch):
    async def fake_gai(host, port, proto=0):
        return [(0, 0, 0, "", ("1.2.3.4", 0)), (0, 0, 0, "", ("2001:db8::1", 0, 0, 0))]

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", fake_gai)
        return await dnsmod._collect_getaddrinfo("a.com", 5)

    cr = asyncio.run(run())
    assert {r.key: r.value for r in cr.records} == {"a.com|A": "1.2.3.4", "a.com|AAAA": "2001:db8::1"}


def test_rotacao_de_ip_vira_um_changed_com_diff():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    try:
        s.apply_scan("a.com", [dns_record("cdn.a.com", "A", ["1.1.1.1", "2.2.2.2"])])
        evs = s.apply_scan("a.com", [dns_record("cdn.a.com", "A", ["1.1.1.1", "3.3.3.3"])])
        assert [(e.event_type, e.key) for e in evs] == [(EventType.CHANGED, "cdn.a.com|A")]
        assert evs[0].metadata["_changes"]["values"] == {
            "old": ["1.1.1.1", "2.2.2.2"], "new": ["1.1.1.1", "3.3.3.3"]}
    finally:
        s.close()
        os.remove(db)


def test_migracao_v8_agrega_estado_sem_rajada_de_eventos():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("a.com", [])                                  # baseline
    s.close()
    con = sqlite3.connect(db)                                  # simula banco v7 (formato antigo)
    con.executemany(
        "INSERT INTO state (target, kind, key, value, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
        [("a.com", "dns", "a.com|A|2.2.2.2", "2.2.2.2", 10.0, 50.0),
         ("a.com", "dns", "a.com|A|1.1.1.1", "1.1.1.1", 5.0, 40.0),
         ("a.com", "dns", "a.com|CNAME|x.cdn.net", "x.cdn.net", 7.0, 30.0)])
    con.execute("PRAGMA user_version = 7")
    con.commit(); con.close()
    s = Storage(db)                                            # migra
    try:
        rows = {r["key"]: r for r in s.all_state(["a.com"])}
        assert set(rows) == {"a.com|A", "a.com|CNAME"}
        assert rows["a.com|A"]["value"] == "1.1.1.1, 2.2.2.2"
        assert rows["a.com|A"]["metadata"] == {"values": ["1.1.1.1", "2.2.2.2"]}
        assert (rows["a.com|A"]["first_seen"], rows["a.com|A"]["last_seen"]) == (5.0, 50.0)
        # 1º scan pós-upgrade com as mesmas respostas: nenhum evento
        evs = s.apply_scan("a.com", [dns_record("a.com", "A", ["2.2.2.2", "1.1.1.1"]),
                                     dns_record("a.com", "CNAME", ["x.cdn.net"])])
        assert evs == []
    finally:
        s.close()
        os.remove(db)


def test_trava_de_ip_privado_le_o_formato_novo():
    recs = [dns_record("h.a.com", "A", ["10.0.0.1", "8.8.8.8"]),
            dns_record("h.a.com", "AAAA", ["::1"]),
            dns_record("h.a.com", "CNAME", ["x.net"])]
    assert _ips_from_dns(recs) == {"10.0.0.1", "8.8.8.8", "::1"}
    # compat: valor sem metadata (ex.: vindo de export) também é lido
    assert _ips_from_dns([Record(Kind.DNS, "h.a.com|A", "1.1.1.1, 10.0.0.9")]) == {"1.1.1.1", "10.0.0.9"}


def test_formatacao_nova_e_antiga():
    novo = Event("a.com", EventType.CHANGED, Kind.DNS, "cdn.a.com|A", "1.1.1.1", "3.3.3.3")
    antigo = Event("a.com", EventType.REMOVED, Kind.DNS, "cdn.a.com|A|9.9.9.9", "9.9.9.9", None)
    assert "1.1.1.1 → 3.3.3.3" in telegram._event_line(novo)
    assert "1.1.1.1 → 3.3.3.3" in webhook._md_line(novo)
    assert "1.1.1.1 → 3.3.3.3" in email._plain_line(novo)
    assert "9.9.9.9" in telegram._event_line(antigo) and "9.9.9.9" in email._plain_line(antigo)


def test_tendencia_ignora_dns():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    try:
        s.apply_scan("a.com", [])
        s.apply_scan("a.com", [dns_record("a.com", "A", ["1.1.1.1"]),
                               Record(Kind.PORT, "a.com:443", "open")])
        hoje = s.events_per_day("a.com", 1)[-1]
        assert hoje["added"] == 1 and hoje["total"] == 1       # só a porta
    finally:
        s.close()
        os.remove(db)


def test_painel_mostra_diff_de_conjunto_legivel():
    from padme.webpanel import _changes_html
    html = _changes_html({"values": {"old": ["1.1.1.1", "2.2.2.2"], "new": ["1.1.1.1"]}})
    assert "values: 1.1.1.1, 2.2.2.2 → 1.1.1.1" in html and "[" not in html
