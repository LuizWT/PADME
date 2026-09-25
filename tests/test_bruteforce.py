"""Testes do bruteforce de subdomínios."""

import asyncio
import os
import tempfile

from padme.collectors import bruteforce


def test_load_words_default():
    assert "www" in bruteforce.load_words()


def test_load_words_file():
    p = tempfile.mktemp(suffix=".txt")
    open(p, "w").write("# comentário\napi\ndev\n\n")
    words = bruteforce.load_words(p)
    os.remove(p)
    assert words == ["api", "dev"]


def test_collect(monkeypatch):
    async def fake_resolve_ips(resolver, host):
        return {"1.2.3.4"} if host.split(".")[0] in ("www", "api") else set()

    monkeypatch.setattr(bruteforce, "_resolve_ips", fake_resolve_ips)
    recs, hosts = asyncio.run(bruteforce.collect("alvo.com", ["www", "api", "zzz"], 5))
    assert hosts == {"www.alvo.com", "api.alvo.com"}
    assert {r.key for r in recs} == {"www.alvo.com", "api.alvo.com"}
