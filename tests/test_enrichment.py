"""Contrato aditivo do webhook, anexo de risco nas notificações e diff semântico
no painel."""

import os
import tempfile

from padme.config import Config
from padme.models import Event, EventType, Kind, Record
from padme.notify.formatting import risk_suffix
from padme.notify.webhook import event_to_dict
from padme.storage import Storage
from padme.webpanel import _render


def _rdp_event():
    return Event("x.com", EventType.ADDED, Kind.PORT, "vpn.x.com:3389", None, "open",
                 metadata={"port": 3389, "_source": "vps-eu", "_collector": "ports",
                           "_context": {"exposure": "internet", "criticality": "critical"}})


def test_webhook_contrato_aditivo():
    d = event_to_dict(_rdp_event())
    assert d["severity"] == "critical"
    assert d["confidence"] == "confirmed"
    assert d["risk"]["rule_id"] == "high-risk-port-added"
    assert "NEW_OPEN_PORT" in d["risk"]["reasons"] and "INTERNET_EXPOSED_ASSET" in d["risk"]["reasons"]
    assert d["source"] == "vps-eu"                     # proveniência no topo
    assert d["context"]["exposure"] == "internet"
    # campos antigos preservados (schema aditivo)
    assert d["kind"] == "port" and d["type"] == "added" and d["metadata"]["port"] == 3389


def test_webhook_changes_no_topo():
    e = Event("x.com", EventType.CHANGED, Kind.HTTP, "https://x.com", "200 | nginx", "403 | nginx",
              metadata={"_changes": {"status": {"old": 200, "new": 403}}})
    d = event_to_dict(e)
    assert d["changes"]["status"] == {"old": 200, "new": 403}


def test_risk_suffix_so_em_elevado():
    base = Event("x.com", EventType.ADDED, Kind.PORT, "x.com:443", None, "open", metadata={"port": 443})
    assert risk_suffix(base) == ""                     # não elevado -> sem ruído
    suf = risk_suffix(_rdp_event())
    assert "⚠" in suf and "acesso remoto" in suf


def test_painel_mostra_changes_semanticos():
    db = tempfile.mktemp(suffix=".db")
    s = Storage(db)
    s.apply_scan("x.com", [])  # baseline
    s.apply_scan("x.com", [Record(Kind.HTTP, "https://x.com", "200 | nginx",
                                   metadata={"status": 200, "server": "nginx"})],
                 observed_scopes={("http", "x.com")})
    # 2º scan real: status muda 200 -> 403 (CHANGED com _changes)
    s.apply_scan("x.com", [Record(Kind.HTTP, "https://x.com", "403 | nginx",
                                   metadata={"status": 403, "server": "nginx"})],
                 observed_scopes={("http", "x.com")})
    cfg = Config(targets=["x.com"], db_path=db)
    html = _render(cfg)
    ev = s.recent_events("x.com")[0]
    s.close(); os.remove(db)
    assert ev.metadata.get("_changes", {}).get("status") == {"old": 200, "new": 403}
    assert "chgdet" in html and "status" in html      # detalhe do campo no painel
