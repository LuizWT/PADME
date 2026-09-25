"""Testes da detecção de Wildcard DNS e da supressão no bruteforce."""

import asyncio

from padme.collectors import bruteforce, wildcard
from padme.collectors.wildcard import Wildcard, classify_probe_ips
from padme.models import Kind


# ── classificação a partir dos IPs das sondas ──────────────────────────────
def test_classify_curinga_ips_iguais():
    wc = classify_probe_ips([{"1.2.3.4"}, {"1.2.3.4"}, {"1.2.3.4"}])
    assert wc.active is True
    assert wc.ips == frozenset({"1.2.3.4"})


def test_classify_intersecao():
    # todas compartilham 1.2.3.4 -> catch-all é a interseção
    wc = classify_probe_ips([{"1.2.3.4", "9.9.9.9"}, {"1.2.3.4"}])
    assert wc.active is True
    assert wc.ips == frozenset({"1.2.3.4"})


def test_classify_sem_curinga_nao_resolve():
    assert classify_probe_ips([set(), set(), set()]).active is False


def test_classify_uma_sonda_so_nao_basta():
    # 1 resposta isolada não é consenso de curinga
    assert classify_probe_ips([{"1.2.3.4"}, set()]).active is False


def test_classify_ips_divergentes_sem_intersecao():
    assert classify_probe_ips([{"1.1.1.1"}, {"2.2.2.2"}]).active is False


# ── Wildcard.matches ────────────────────────────────────────────────────────
def test_matches_subconjunto_do_catchall():
    wc = Wildcard(active=True, ips=frozenset({"1.2.3.4", "5.6.7.8"}))
    assert wc.matches({"1.2.3.4"}) is True          # cai no catch-all -> artefato
    assert wc.matches({"9.9.9.9"}) is False         # IP próprio -> host real
    assert wc.matches(set()) is False               # não resolveu -> não suprime


def test_matches_inativo_nunca_suprime():
    assert Wildcard(active=False).matches({"1.2.3.4"}) is False


# ── detect() (wrapper de rede, resolver monkeypatchado) ─────────────────────
def test_detect_curinga(monkeypatch):
    async def fake_resolve_ips(resolver, host):
        return {"1.2.3.4"}  # tudo resolve pro mesmo IP -> curinga

    monkeypatch.setattr(wildcard, "_resolve_ips", fake_resolve_ips)
    wc = asyncio.run(wildcard.detect("alvo.com", timeout=5, probes=3))
    assert wc.active is True and wc.ips == frozenset({"1.2.3.4"})


def test_detect_sem_curinga(monkeypatch):
    async def fake_resolve_ips(resolver, host):
        return set()  # nada resolve -> sem curinga

    monkeypatch.setattr(wildcard, "_resolve_ips", fake_resolve_ips)
    wc = asyncio.run(wildcard.detect("alvo.com", timeout=5, probes=3))
    assert wc.active is False


def test_detect_probes_insuficiente():
    # probes < 2 nunca detecta curinga (não há como formar consenso)
    assert asyncio.run(wildcard.detect("alvo.com", timeout=5, probes=1)).active is False


# ── supressão no bruteforce ─────────────────────────────────────────────────
def test_bruteforce_suprime_catchall(monkeypatch):
    resolve_map = {
        "www.alvo.com": {"1.2.3.4"},   # catch-all -> deve ser suprimido
        "api.alvo.com": {"9.9.9.9"},   # IP próprio -> host real, mantém
        "dev.alvo.com": set(),         # não resolve -> ignora
    }

    async def fake_resolve(resolver, host):
        return set(resolve_map.get(host, set()))

    monkeypatch.setattr(bruteforce, "_resolve_ips", fake_resolve)
    wc = Wildcard(active=True, ips=frozenset({"1.2.3.4"}))
    recs, hosts = asyncio.run(
        bruteforce.collect("alvo.com", ["www", "api", "dev"], timeout=5,
                           concurrency=10, wildcard=wc)
    )
    assert hosts == {"api.alvo.com"}
    assert [r.kind for r in recs] == [Kind.SUBDOMAIN]
    assert recs[0].key == "api.alvo.com"


def test_bruteforce_sem_curinga_mantem_todos_que_resolvem(monkeypatch):
    resolve_map = {"www.alvo.com": {"1.2.3.4"}, "api.alvo.com": {"9.9.9.9"}}

    async def fake_resolve(resolver, host):
        return set(resolve_map.get(host, set()))

    monkeypatch.setattr(bruteforce, "_resolve_ips", fake_resolve)
    recs, hosts = asyncio.run(
        bruteforce.collect("alvo.com", ["www", "api"], timeout=5, wildcard=None)
    )
    assert hosts == {"www.alvo.com", "api.alvo.com"}
