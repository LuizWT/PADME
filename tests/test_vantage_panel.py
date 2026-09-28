"""Multi-vantage no painel: consolida o estado local + exports de outras fontes
reutilizando merge_exports (mesma verdade do `padme merge`)."""

import json
import os
import tempfile

from padme.config import Config
from padme.models import Kind, Record
from padme.storage import Storage
from padme.webpanel import render_vantage


def _setup(tmp):
    # estado local (source=casa)
    db = os.path.join(tmp, "padme.db")
    s = Storage(db)
    s.apply_scan("a.com", [
        Record(Kind.SUBDOMAIN, "api.a.com", "live"),
        Record(Kind.HTTP, "https://a.com", "200 | nginx"),
    ])
    s.close()
    # export de outra fonte (source=vps) num diretório de vantage
    vdir = os.path.join(tmp, "vantage")
    os.makedirs(vdir)
    rows = [
        {"source": "vps", "target": "a.com", "kind": "subdomain", "key": "api.a.com", "value": "live"},
        {"source": "vps", "target": "a.com", "kind": "http", "key": "https://a.com", "value": "403 | nginx"},
        {"source": "vps", "target": "a.com", "kind": "subdomain", "key": "vpn.a.com", "value": "live"},
    ]
    with open(os.path.join(vdir, "vps.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f)
    return Config(targets=["a.com"], db_path=db, source="casa"), vdir


def test_render_vantage_presenca_e_valor():
    with tempfile.TemporaryDirectory() as tmp:
        cfg, vdir = _setup(tmp)
        cfg.web.vantage_dir = vdir
        html = render_vantage(cfg)
    assert "casa" in html and "vps" in html                 # fontes listadas
    assert "divergência de presença" in html
    assert "vpn.a.com" in html                              # só em vps -> presença
    assert "divergência de valor" in html
    assert "https://a.com" in html                          # valor difere -> valor
    # api.a.com tem o mesmo valor nas duas fontes -> não é divergência de valor
    assert "403 | nginx" in html and "200 | nginx" in html  # valor por fonte visível


def test_render_vantage_export_invalido_e_pulado():
    with tempfile.TemporaryDirectory() as tmp:
        cfg, vdir = _setup(tmp)
        with open(os.path.join(vdir, "quebrado.json"), "w", encoding="utf-8") as f:
            f.write("{ isso não é json válido")
        cfg.web.vantage_dir = vdir
        html = render_vantage(cfg)
    assert "quebrado.json" in html and "inválido" in html   # avisado, não derruba
    assert "<html" in html.lower()                          # página ainda renderiza


def test_render_vantage_sem_dir_so_local():
    with tempfile.TemporaryDirectory() as tmp:
        cfg, _ = _setup(tmp)
        cfg.web.vantage_dir = ""                            # sem outras fontes
        html = render_vantage(cfg)
    assert "casa" in html
    assert "sem divergência" in html                        # uma fonte só -> nada diverge
