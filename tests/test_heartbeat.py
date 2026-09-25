"""Testes do heartbeat / dead-man's switch."""

import asyncio

from padme.heartbeat import Heartbeat


def test_should_beat_cada_n_ciclos():
    hb = Heartbeat(url="http://x", every_cycles=3)
    beats = [c for c in range(1, 11) if hb.should_beat(c)]
    assert beats == [1, 4, 7, 10]


def test_should_beat_todo_ciclo_por_padrao():
    hb = Heartbeat(url="http://x")
    assert all(hb.should_beat(c) for c in range(1, 6))


def test_ping_url_sucesso_e_falha():
    hb = Heartbeat(url="https://hc.example/abc/")
    assert hb.ping_url(True) == "https://hc.example/abc/"
    assert hb.ping_url(False) == "https://hc.example/abc/fail"


def test_ping_url_sem_url():
    assert Heartbeat(file="/tmp/x").ping_url(True) is None


def test_desligado_sem_url_nem_arquivo():
    assert Heartbeat().enabled is False


def test_beat_grava_arquivo(tmp_path):
    f = tmp_path / "alive.txt"
    hb = Heartbeat(file=str(f))  # só arquivo, sem rede
    ok = asyncio.run(hb.beat(cycle=1, ok=True))
    assert ok is True
    conteudo = f.read_text()
    assert "cycle=1" in conteudo and "status=ok" in conteudo


def test_beat_nao_bate_fora_do_intervalo(tmp_path):
    f = tmp_path / "alive.txt"
    hb = Heartbeat(file=str(f), every_cycles=5)
    # ciclo 2 não deve bater -> arquivo não é criado
    assert asyncio.run(hb.beat(cycle=2)) is False
    assert not f.exists()


class _FakeResp:
    def raise_for_status(self):
        return None


class _FakeClient:
    def __init__(self):
        self.calls = []

    async def get(self, url, timeout=None):
        self.calls.append(url)
        return _FakeResp()


def test_beat_faz_ping_com_status(tmp_path):
    client = _FakeClient()
    hb = Heartbeat(url="https://hc.example/abc")
    assert asyncio.run(hb.beat(cycle=1, ok=False, client=client)) is True
    assert client.calls == ["https://hc.example/abc/fail"]


def test_beat_ping_falha_nao_derruba(tmp_path):
    class _Boom:
        async def get(self, url, timeout=None):
            raise RuntimeError("rede caiu")

    hb = Heartbeat(url="https://hc.example/abc")
    # falha do ping é engolida -> retorna False, mas não propaga exceção
    assert asyncio.run(hb.beat(cycle=1, ok=True, client=_Boom())) is False
