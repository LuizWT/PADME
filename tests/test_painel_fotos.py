"""Fotos do HTML do painel: renderiza as páginas a partir de um banco fixo, com
relógio congelado, e compara byte a byte com o que está gravado em
`tests/fotos_painel/`.

Servem de rede de segurança para refatorar o painel sem mudar o que ele mostra.
Uma mudança VISUAL intencional regrava as fotos:

    PADME_REGRAVAR_FOTOS=1 pytest tests/test_painel_fotos.py

e o diff das fotos entra na mesma PR, para a revisão ver o que mudou na tela.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import time
from pathlib import Path

import pytest

from padme import webpanel as paginas  # importado antes de congelar o relógio
from padme.config import Config
from padme.findings import derive
from padme.models import Kind, Record
from padme.storage import Storage

FOTOS = Path(__file__).parent / "fotos_painel"
T0 = 1_790_000_000.0          # 2026-09-21 13:46:40 UTC
CSRF = "c" * 64
TK = {"cname": "acme.github.io", "service": "GitHub Pages", "reason": "CNAME dangling (NXDOMAIN)"}


class _Relogio:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def relogio(monkeypatch):
    """Congela time.time() e datetime.now() em todo o pacote, em UTC."""
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    rel = _Relogio(T0)
    monkeypatch.setattr(time, "time", rel)

    class _Congelado(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime.fromtimestamp(rel.t, tz)

    for nome, mod in list(sys.modules.items()):
        if nome.startswith("padme") and getattr(mod, "datetime", None) is _dt.datetime:
            monkeypatch.setattr(mod, "datetime", _Congelado)
    yield rel
    monkeypatch.delenv("TZ")
    time.tzset()


def _banco(db: str, rel: _Relogio) -> None:
    s = Storage(db)
    try:
        rel.t = T0 - 10 * 86400
        s.apply_scan("acme.com", [])                       # baseline
        s.apply_scan("loja.dev", [])
        rel.t = T0 - 5 * 86400
        s.apply_scan("acme.com", [
            Record(Kind.SUBDOMAIN, "api.acme.com", "live"),
            Record(Kind.SUBDOMAIN, "blog.acme.com", "quiet"),
            Record(Kind.DNS, "api.acme.com|A", "203.0.113.10",
                   metadata={"values": ["203.0.113.10", "203.0.113.11"]}),
            Record(Kind.PORT, "api.acme.com:22", "open · SSH-2.0-OpenSSH_9.6p1",
                   metadata={"port": 22, "service": "ssh", "product": "OpenSSH",
                             "version": "9.6p1"}),
            Record(Kind.PORT, "api.acme.com:3389", "open", metadata={"port": 3389}),
            Record(Kind.HTTP, "api.acme.com", "200 | nginx | API",
                   metadata={"status": 200, "server": "nginx", "title": "API",
                             "tech": ["nginx"]}),
            Record(Kind.HTTPSEC, "api.acme.com", "falta: csp, hsts",
                   metadata={"missing": ["csp", "hsts"]}),
            Record(Kind.TLS, "api.acme.com:443", "LE | 2026-12-01 | ab12",
                   metadata={"issuer": "LE", "not_after": "2026-12-01",
                             "fingerprint": "ab12", "sans": ["api.acme.com"]}),
            Record(Kind.CERT_EXPIRY, "api.acme.com:443", "expira em 6 dia(s)",
                   metadata={"days_left": 6, "not_after": "2026-09-27"}),
            Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages", metadata=dict(TK)),
            Record(Kind.WILDCARD, "*.acme.com", "198.51.100.7"),
            Record(Kind.MAILSEC, "acme.com|SPF-ORPHAN|vendor-livre.net",
                   "vendor-livre.net (free) via _spf.vendor-livre.net",
                   metadata={"type": "spf-orphan", "registrable": "vendor-livre.net",
                             "availability": "free"}),
            Record(Kind.NS, "acme.com", "ns1.dns.net,ns2.dns.net"),
        ])
        s.apply_scan("loja.dev", [
            Record(Kind.HTTP, "loja.dev", "200 | cloudflare | Loja",
                   metadata={"status": 200, "server": "cloudflare", "title": "Loja"}),
        ])
        rel.t = T0 - 86400
        s.apply_scan("acme.com", [                         # mudanças e remoções
            Record(Kind.SUBDOMAIN, "api.acme.com", "live"),
            Record(Kind.SUBDOMAIN, "blog.acme.com", "quiet"),
            Record(Kind.SUBDOMAIN, "novo.acme.com", "live"),
            Record(Kind.DNS, "api.acme.com|A", "203.0.113.12",
                   metadata={"values": ["203.0.113.12"]}),
            Record(Kind.PORT, "api.acme.com:22", "open · SSH-2.0-OpenSSH_9.7p1",
                   metadata={"port": 22, "service": "ssh", "product": "OpenSSH",
                             "version": "9.7p1"}),
            Record(Kind.HTTP, "api.acme.com", "403 | nginx | Proibido",
                   metadata={"status": 403, "server": "nginx", "title": "Proibido"}),
            Record(Kind.HTTPSEC, "api.acme.com", "falta: csp, hsts",
                   metadata={"missing": ["csp", "hsts"]}),
            Record(Kind.TLS, "api.acme.com:443", "LE | 2026-12-01 | ab12",
                   metadata={"issuer": "LE", "not_after": "2026-12-01",
                             "fingerprint": "ab12", "sans": ["api.acme.com"]}),
            Record(Kind.CERT_EXPIRY, "api.acme.com:443", "expira em 6 dia(s)",
                   metadata={"days_left": 6, "not_after": "2026-09-27"}),
            Record(Kind.TAKEOVER, "blog.acme.com", "GitHub Pages", metadata=dict(TK)),
            Record(Kind.WILDCARD, "*.acme.com", "198.51.100.7"),
            Record(Kind.MAILSEC, "acme.com|SPF-ORPHAN|vendor-livre.net",
                   "vendor-livre.net (free) via _spf.vendor-livre.net",
                   metadata={"type": "spf-orphan", "registrable": "vendor-livre.net",
                             "availability": "free"}),
            Record(Kind.NS, "acme.com", "ns1.dns.net,ns2.dns.net"),
        ])
        s.update_health("acme.com", error_count=1, partial=True, duration_ms=1234,
                        collectors={"http": {"status": "ok", "ok": 3, "fail": 0},
                                    "tls": {"status": "partial", "ok": 1, "fail": 1},
                                    "ports": {"status": "error", "ok": 0, "fail": 2},
                                    "dns": {"status": "ok", "ok": 3, "fail": 0}},
                        inconclusive=2)
        s.update_health("loja.dev", error_count=0, partial=False, duration_ms=321,
                        collectors={"http": {"status": "ok", "ok": 1, "fail": 0}})
        kinds: dict = {}
        for r in s.all_state(["acme.com"]):
            kinds.setdefault(r["kind"], []).append(r)
        s.sync_findings("acme.com", derive("acme.com", kinds), now=rel.t)
        rows = s.finding_rows()
        rel.t = T0 - 3600
        wild = next(f for f, r in rows.items() if r["kind"] == "wildcard")
        s.set_finding_status(wild, "accept", reason="curinga do CDN", actor="ana")
        cert = next(f for f, r in rows.items() if r["kind"] == "cert_expiry")
        s.set_finding_status(cert, "ack", reason="renovação agendada", actor="bia")
    finally:
        s.close()
    rel.t = T0


def _vantage(dirpath: Path) -> None:
    dirpath.mkdir()
    linha = {"target": "acme.com", "kind": "subdomain", "key": "so-daqui.acme.com",
             "value": "live", "first_seen": T0 - 86400, "last_seen": T0, "metadata": {}}
    (dirpath / "vps-eu.json").write_text(json.dumps([dict(linha, source="vps-eu")]),
                                         encoding="utf-8")


@pytest.fixture
def cfg(tmp_path, relogio):
    db = str(tmp_path / "padme.db")
    _banco(db, relogio)
    vdir = tmp_path / "vantage"
    _vantage(vdir)
    c = Config(targets=["acme.com", "loja.dev", "sem-scan.org"], db_path=db, source="casa")
    c.web.vantage_dir = str(vdir)
    return c


def _confere(nome: str, conteudo: str) -> None:
    alvo = FOTOS / nome
    if os.environ.get("PADME_REGRAVAR_FOTOS"):
        FOTOS.mkdir(exist_ok=True)
        alvo.write_text(conteudo, encoding="utf-8", newline="")
        return
    assert alvo.exists(), f"foto {nome} não existe: rode com PADME_REGRAVAR_FOTOS=1"
    with open(alvo, encoding="utf-8", newline="") as f:   # read_text(newline=) só no 3.13+
        esperado = f.read()
    assert conteudo == esperado, (
        f"o HTML de {nome} mudou. Se a mudança na tela é intencional, regrave com "
        "PADME_REGRAVAR_FOTOS=1 e inclua o diff da foto na PR.")


def test_foto_visao_geral(cfg):
    _confere("visao_geral.html", paginas._render(cfg))


def test_foto_visao_geral_com_acoes(cfg):
    _confere("visao_geral_acoes.html", paginas._render(cfg, authed=True, csrf=CSRF))


def test_foto_painel_exposto(cfg):
    _confere("exposto.html", paginas._render(cfg, exposed=True))


def test_foto_dossie_do_alvo(cfg):
    _confere("dossie_acme.html", paginas._render(cfg, only="acme.com", csrf=CSRF))


def test_foto_filtro_por_substring(cfg):
    _confere("filtro_loja.html", paginas._render(cfg, only="loja"))


def test_foto_vantage(cfg):
    _confere("vantage.html", paginas.render_vantage(cfg))


def test_foto_export(cfg):
    corpo_json, tipo_json = paginas.render_export(cfg, None, "json")
    corpo_csv, tipo_csv = paginas.render_export(cfg, "acme.com", "csv")
    _confere("export.json", f"{tipo_json}\n{corpo_json}")
    _confere("export_acme.csv", f"{tipo_csv}\n{corpo_csv}")


def test_foto_sem_banco(tmp_path, relogio):
    vazio = Config(targets=["acme.com"], db_path=str(tmp_path / "nao-existe.db"))
    _confere("sem_banco.html", paginas._render(vazio))


def test_fotos_sao_deterministicas(cfg):
    a = paginas._render(cfg, csrf=CSRF)
    b = paginas._render(cfg, csrf=CSRF)
    assert a == b
