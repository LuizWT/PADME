"""Testes da detecção de subdomain takeover."""

import asyncio

from padme.collectors import takeover
from padme.models import Kind


def test_match_service():
    assert takeover.match_service("felipe.github.io")["service"] == "GitHub Pages"
    assert takeover.match_service("x.s3.amazonaws.com")["service"] == "AWS S3"
    assert takeover.match_service("app.azurewebsites.net")["nxdomain"] is True
    assert takeover.match_service("exemplo.com") is None


def _run(host, cname, resolves, body, monkeypatch):
    async def fake_cname(h, t):
        return cname, resolves

    async def fake_body(client, h, cache=None):
        return body

    monkeypatch.setattr(takeover, "_cname_target", fake_cname)
    monkeypatch.setattr(takeover, "_body", fake_body)
    return asyncio.run(takeover.collect_host(host, client=None, timeout=5))


def test_fingerprint_vulneravel(monkeypatch):
    recs = _run(
        "blog.alvo.com", "alvo.github.io", True,
        "There isn't a GitHub Pages site here.", monkeypatch,
    )
    assert len(recs) == 1
    assert recs[0].kind == Kind.TAKEOVER
    assert "GitHub Pages" in recs[0].value


def test_fingerprint_seguro(monkeypatch):
    # CNAME casa serviço, mas o corpo é um site normal -> não vulnerável
    recs = _run("blog.alvo.com", "alvo.github.io", True, "<html>site ok</html>", monkeypatch)
    assert recs == []


def test_azure_nxdomain(monkeypatch):
    recs = _run("api.alvo.com", "app.azurewebsites.net", False, "", monkeypatch)
    assert len(recs) == 1
    assert "Azure" in recs[0].value
    assert "NXDOMAIN" in recs[0].value


def test_sem_cname(monkeypatch):
    recs = _run("alvo.com", None, True, "", monkeypatch)
    assert recs == []


def test_usa_cache_sem_refetch(monkeypatch):
    # com cache preenchido, não deve tocar a rede (client=None provaria erro)
    async def fake_cname(h, t):
        return "alvo.github.io", True

    monkeypatch.setattr(takeover, "_cname_target", fake_cname)
    cache = {"https://blog.alvo.com": "There isn't a GitHub Pages site here."}
    recs = asyncio.run(takeover.collect_host("blog.alvo.com", client=None, timeout=5, cache=cache))
    assert len(recs) == 1 and recs[0].kind == Kind.TAKEOVER
