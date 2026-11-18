"""Detalhe dos CVEs de um problema de versão: link no OSV na lista do painel,
no inventário do dossiê, nos alertas de cada canal e no `padme finding show`."""

from padme import vulnrefs
from padme.cli import main
from padme.findings import derive
from padme.models import Event, EventType, Kind, Record
from padme.notify.email import format_events_plain
from padme.notify.telegram import format_events
from padme.notify.webhook import event_to_dict, format_events_md
from padme.storage import Storage
from padme.web.html import _cve_fp
from padme.web.problems import _problem_row

KEY = "203.0.113.7:22"
VULNS = [
    {"id": "CVE-2024-6387", "severity": "high", "score": 8.1, "fixed": "1:9.2p1-2+deb12u3"},
    {"id": "CVE-2025-26465", "severity": "medium", "score": 6.8, "fixed": "1:9.2p1-2+deb12u5"},
    {"id": "CVE-2023-51385", "severity": "medium", "score": 6.5, "fixed": "1:9.2p1-2+deb12u2"},
    {"id": "CVE-2023-48795", "severity": "medium", "score": 5.9, "fixed": "1:9.2p1-2+deb12u2"},
    {"id": "DEBIAN-X-1", "severity": "unknown", "score": None, "fixed": None},
]
MD = {"port": 22, "package": "openssh", "ecosystem": "Debian:12", "version": "1:9.2p1-2+deb12u1",
      "cves": [v["id"] for v in VULNS], "max_severity": "high", "max_score": 8.1,
      "vulns": VULNS, "unfixed": 7, "confidence": "high"}
VALOR = "openssh 1:9.2p1-2+deb12u1 · 5 CVEs, o pior CVE-2024-6387 (high 8.1)"


def _ev(tipo=EventType.ADDED, md=None):
    return Event("203.0.113.7", tipo, Kind.VULN, KEY,
                 None if tipo == EventType.ADDED else "antes",
                 None if tipo == EventType.REMOVED else VALOR, metadata=md or dict(MD))


def test_refs_link_rotulo_e_novos_no_changed():
    assert vulnrefs.osv_url("CVE-2024-6387") == "https://osv.dev/vulnerability/CVE-2024-6387"
    assert vulnrefs.osv_url("a b/c") == "https://osv.dev/vulnerability/a%20b%2Fc"
    rs = vulnrefs.refs(MD)
    assert [r["id"] for r in rs] == [v["id"] for v in VULNS]          # ordem do metadata
    assert rs[0]["label"] == "high 8.1" and rs[-1]["label"] == "unknown"
    novos = vulnrefs.refs(MD, {"cves": {"old": ["CVE-2024-6387"],
                                        "new": ["CVE-2024-6387", "CVE-2025-26465"]}})
    assert [r["id"] for r in novos] == ["CVE-2025-26465"]
    so_diminuiu = vulnrefs.refs(MD, {"cves": {"old": [v["id"] for v in VULNS] + ["CVE-X"],
                                              "new": [v["id"] for v in VULNS]}})
    assert len(so_diminuiu) == len(VULNS)
    assert vulnrefs.refs({}) == [] and vulnrefs.refs(None) == []


def test_telegram_traz_os_piores_com_link_e_o_resto_em_numero():
    msg = format_events("203.0.113.7", [_ev()])
    assert '<a href="https://osv.dev/vulnerability/CVE-2024-6387">CVE-2024-6387</a> (high 8.1)' in msg
    assert "CVE-2023-51385" in msg and "CVE-2023-48795" not in msg     # só 3
    assert "· +2" in msg


def test_alerta_de_mudanca_destaca_so_o_cve_novo():
    md = dict(MD, _changes={"cves": {"old": ["CVE-2024-6387"],
                                     "new": ["CVE-2024-6387", "CVE-2025-26465"]}})
    msg = format_events("203.0.113.7", [_ev(EventType.CHANGED, md)])
    assert "vulnerability/CVE-2025-26465" in msg
    assert "vulnerability/CVE-2024-6387" not in msg


def test_resolvido_nao_traz_links():
    assert "osv.dev" not in format_events("203.0.113.7", [_ev(EventType.REMOVED)])
    assert "references" not in event_to_dict(_ev(EventType.REMOVED))


def test_email_discord_e_webhook():
    texto = format_events_plain("203.0.113.7", [_ev()])
    assert "CVE-2024-6387 (high 8.1): https://osv.dev/vulnerability/CVE-2024-6387" in texto
    assert "e mais 2" in texto
    md = format_events_md("203.0.113.7", [_ev()])
    assert "[CVE-2024-6387](<https://osv.dev/vulnerability/CVE-2024-6387>) (high 8.1)" in md
    refs = event_to_dict(_ev())["references"]
    assert len(refs) == len(VULNS)                                     # webhook: lista completa
    assert refs[0] == {"id": "CVE-2024-6387", "url": "https://osv.dev/vulnerability/CVE-2024-6387",
                       "severity": "high", "score": 8.1, "fixed": "1:9.2p1-2+deb12u3"}


def test_outros_tipos_nao_mudam():
    ev = Event("acme.com", EventType.ADDED, Kind.PORT, "acme.com:22", None, "open",
               metadata={"port": 22})
    assert "osv.dev" not in format_events("acme.com", [ev])
    assert "references" not in event_to_dict(ev)


def test_painel_lista_os_cves_com_link_e_lembra_aberto():
    (f,) = derive("203.0.113.7", {"vuln": [{"key": KEY, "value": VALOR, "metadata": MD}]})
    assert [c["id"] for c in f["cves"]] == [v["id"] for v in VULNS] and f["unfixed"] == 7
    html = _problem_row({**f, "status": "open", "row": {}})
    assert "<details class=cves data-persist='cves-" in html
    assert "5 CVEs com correção" in html
    assert ("<a href='https://osv.dev/vulnerability/CVE-2024-6387' target=_blank "
            "rel='noopener noreferrer'>CVE-2024-6387</a>") in html
    assert "corrige em 1:9.2p1-2+deb12u3" in html
    assert "mais 7 sem correção publicada na distro" in html
    # outros problemas não ganham a lista
    (t,) = derive("acme.com", {"wildcard": [{"key": "*.acme.com", "value": "1.2.3.4"}]})
    assert "details class=cves" not in _problem_row({**t, "status": "open", "row": {}})


def test_inventario_do_dossie_mostra_os_piores_cves():
    html = _cve_fp(MD)
    assert html.count("class=cvea") == 3 and "+2" in html
    assert "https://osv.dev/vulnerability/CVE-2024-6387" in html
    assert _cve_fp({}) == ""


def test_finding_show_lista_os_cves(tmp_path, capsys):
    db = str(tmp_path / "p.db")
    s = Storage(db)
    s.apply_scan("203.0.113.7", [Record(Kind.VULN, KEY, VALOR, metadata=MD)])
    rows = s.all_state(["203.0.113.7"])
    s.sync_findings("203.0.113.7", derive("203.0.113.7", {"vuln": rows}))
    fid = next(iter(s.finding_rows()))
    s.close()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"targets: [203.0.113.7]\nscope_confirmed: true\ndb_path: {db}\n"
                   "network:\n  allow_private_ips: true\n", encoding="utf-8")
    assert main(["-c", str(cfg), "finding", "show", fid]) == 0
    out = capsys.readouterr().out
    assert "CVEs com correção (5):" in out
    assert "https://osv.dev/vulnerability/CVE-2024-6387" in out
    assert "corrige em 1:9.2p1-2+deb12u3" in out
    assert "mais 7 sem correção publicada na distro" in out
