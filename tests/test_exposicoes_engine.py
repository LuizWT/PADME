"""Exposições HTTP do lado do engine: quando a bateria roda, o intervalo por
host, e o ciclo de vida do problema (resolve com ciclo completo, preserva
quando inconclusivo). O coletor é substituído por um falso com uma assinatura
fictícia: aqui só importa a integração, não a detecção."""

import asyncio
import time

import pytest

from padme import engine as engine_mod
from padme.config import Config
from padme.engine import _EXPOSURE_META, Engine
from padme.models import CollectionResult, EventType, Kind, Record
from padme.risk import Level, assess
from padme.storage import Storage


class Falso:
    """Coletores falsos de HTTP e de exposição, com estado controlado pelo teste."""

    def __init__(self):
        self.http_ok = True
        self.achado = True          # a bateria encontra a assinatura?
        self.exposicao_ok = True    # a bateria terminou (False = timeout/erro)
        self.chamadas: list[tuple[str, bool]] = []

    async def http(self, host, client, *a, **k):
        recs = [Record(Kind.HTTP, f"https://{host}", "200 | x | ")] if self.http_ok else []
        return CollectionResult(records=recs, ok=self.http_ok)

    async def exposicao(self, host, client, follow_redirects=False, allow_private=False):
        self.chamadas.append((host, allow_private))
        recs = []
        if self.achado and self.exposicao_ok:
            recs = [Record(Kind.EXPOSURE, f"{host}|teste-1", "teste-1 · 200",
                           metadata={"severity": "high", "check_id": "teste-1"})]
        return CollectionResult(records=recs, ok=self.exposicao_ok)


def _engine(monkeypatch, tmp_path, target, allow_private=True):
    falso = Falso()
    monkeypatch.setattr(engine_mod.http, "collect_host", falso.http)
    monkeypatch.setattr(engine_mod.exposure, "collect_host", falso.exposicao)
    db = str(tmp_path / "padme.db")
    cfg = Config(targets=[target], db_path=db)
    c = cfg.collectors
    c.subdomains = c.wildcard = c.dns_records = c.dns = c.takeover = False
    c.tls = c.favicon = c.ports = False
    c.exposures = True
    cfg.network.allow_private_ips = allow_private
    storage = Storage(db)
    return Engine(cfg, storage), storage, falso


def _scan(eng, target):
    return eng.apply(asyncio.run(eng.scan_target(target)))


def _exposicoes(storage, target):
    return [r for r in storage.all_state([target]) if r["kind"] == "exposure"]


@pytest.mark.parametrize("target", ["alvo.example", "203.0.113.7", "203.0.113.4/30"])
def test_roda_em_dominio_em_ip_e_em_faixa(monkeypatch, tmp_path, target):
    eng, storage, falso = _engine(monkeypatch, tmp_path, target)
    _scan(eng, target)
    sondados = {h for h, _ in falso.chamadas}
    assert sondados and all(f"{h}|teste-1" in {r["key"] for r in _exposicoes(storage, target)}
                            for h in sondados)
    storage.close()


def test_so_roda_quando_o_http_respondeu(monkeypatch, tmp_path):
    eng, storage, falso = _engine(monkeypatch, tmp_path, "203.0.113.7")
    falso.http_ok = False
    _scan(eng, "203.0.113.7")
    assert falso.chamadas == [] and _exposicoes(storage, "203.0.113.7") == []
    storage.close()


def test_ip_privado_nao_e_sondado_sem_allow_private(monkeypatch, tmp_path):
    eng, storage, falso = _engine(monkeypatch, tmp_path, "10.0.0.5", allow_private=False)
    _scan(eng, "10.0.0.5")
    assert falso.chamadas == []
    storage.close()


def test_intervalo_entre_baterias_e_ciclo_de_vida(monkeypatch, tmp_path):
    host = "203.0.113.7"
    eng, storage, falso = _engine(monkeypatch, tmp_path, host)

    # 1. baseline: a bateria roda e o problema entra no estado
    assert _scan(eng, host) == []
    assert len(falso.chamadas) == 1 and len(_exposicoes(storage, host)) == 1

    # 2. dentro do intervalo a bateria não roda; o escopo não foi observado,
    #    então o problema fica, mesmo que agora não fosse achado
    falso.achado = False
    assert [e for e in _scan(eng, host) if e.kind == Kind.EXPOSURE] == []
    assert len(falso.chamadas) == 1 and len(_exposicoes(storage, host)) == 1

    # 3. intervalo vencido, mas a bateria não terminou: inconclusivo, fica, e a
    #    próxima varredura tenta de novo (o carimbo não é atualizado)
    vencido = str(time.time() - 25 * 3600)
    storage.set_meta(_EXPOSURE_META + host, vencido)
    falso.exposicao_ok = False
    assert [e for e in _scan(eng, host) if e.kind == Kind.EXPOSURE] == []
    assert len(falso.chamadas) == 2 and len(_exposicoes(storage, host)) == 1
    assert storage.get_meta(_EXPOSURE_META + host) == vencido

    # 4. ciclo completo sem a assinatura: resolvido
    falso.exposicao_ok = True
    (ev,) = [e for e in _scan(eng, host) if e.kind == Kind.EXPOSURE]
    assert ev.event_type == EventType.REMOVED and ev.key == f"{host}|teste-1"
    assert assess(ev).level == Level.MEDIUM
    assert _exposicoes(storage, host) == []
    assert float(storage.get_meta(_EXPOSURE_META + host)) > float(vencido)
    storage.close()


def test_exposicao_nova_alerta_pela_severidade(monkeypatch, tmp_path):
    host = "203.0.113.7"
    eng, storage, falso = _engine(monkeypatch, tmp_path, host)
    falso.achado = False
    _scan(eng, host)                                      # baseline sem achado
    storage.set_meta(_EXPOSURE_META + host, str(time.time() - 25 * 3600))
    falso.achado = True
    (ev,) = [e for e in _scan(eng, host) if e.kind == Kind.EXPOSURE]
    assert ev.event_type == EventType.ADDED
    assert assess(ev).level == Level.HIGH and "EXPOSED_FILE" in assess(ev).reasons
    storage.close()
