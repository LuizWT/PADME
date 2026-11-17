"""CVEs por versão de serviço via OSV (padme.osv + engine._vulns).

As respostas abaixo reproduzem, enxutas, a forma das respostas reais do
api.osv.dev (conferidas em 2026-11-17): DEBIAN-CVE-*/UBUNTU-CVE-* com o CVE em
`upstream`, avisos DSA/DLA/USN com os CVEs (e os ids da distro) em `upstream`,
registro sem correção só com `introduced`, e o /v1/querybatch devolvendo
results[].vulns[].id. Nenhum teste toca a rede: tudo passa por um
httpx.MockTransport."""

import asyncio
import json
import sqlite3

import httpx
import pytest

from padme import engine as engine_mod
from padme import osv
from padme.collectors import ports as ports_mod
from padme.config import Config
from padme.engine import Engine
from padme.evidence import evidence_of
from padme.findings import derive
from padme.models import CollectionResult, Event, EventType, Kind, Record, scope_of
from padme.risk import Confidence, Level, assess
from padme.storage import Storage

# ── banner -> pacote ────────────────────────────────────────────────────────

_SSH_DEB12 = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"


def _md(port, banner):
    return {"port": port, "banner": banner, **ports_mod.fingerprint(port, banner)}


@pytest.mark.parametrize("port,banner,esperado", [
    (22, _SSH_DEB12, ("Debian:12", "openssh", "1:9.2p1-2+deb12u3", "high")),
    (22, "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
     ("Debian:11", "openssh", "1:8.4p1-5+deb11u3", "high")),
    # sem +debNNuN: a versão upstream diz a versão da distro (só uma traz 9.2p1)
    (22, "SSH-2.0-OpenSSH_9.2p1 Debian-2", ("Debian:12", "openssh", "1:9.2p1-2", "medium")),
    (22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
     ("Ubuntu:22.04:LTS", "openssh", "1:8.9p1-3ubuntu0.10", "medium")),
    (3306, "MariaDB 10.11.6-0+deb12u1", ("Debian:12", "mariadb", "1:10.11.6-0+deb12u1", "high")),
    (3306, "MariaDB 10.5.23-0+deb11u1",
     ("Debian:11", "mariadb-10.5", "1:10.5.23-0+deb11u1", "high")),
    (3306, "MariaDB 10.6.16-0ubuntu0.22.04.1",
     ("Ubuntu:22.04:LTS", "mariadb-10.6", "1:10.6.16-0ubuntu0.22.04.1", "high")),
    (3306, "MySQL 8.0.36-0ubuntu0.22.04.1",
     ("Ubuntu:22.04:LTS", "mysql-8.0", "8.0.36-0ubuntu0.22.04.1", "high")),
])
def test_banner_com_revisao_da_distro_vira_pacote(port, banner, esperado):
    pkg = osv.package_of(_md(port, banner))
    assert pkg is not None
    assert (pkg.ecosystem, pkg.name, pkg.version, pkg.confidence) == esperado


@pytest.mark.parametrize("port,banner", [
    (22, "SSH-2.0-OpenSSH_9.6"),                         # upstream puro, sem distro
    (22, "SSH-2.0-OpenSSH_9.6p1"),
    (22, "SSH-2.0-dropbear_2022.83"),
    (22, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3~bpo11+1"),  # backport
    (22, "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"),      # Debian 9: fora da tabela
    (22, "SSH-2.0-OpenSSH_9.9p1 Debian-1"),              # upstream de nenhuma versão estável
    (22, "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7"),     # Ubuntu não-LTS
    (3306, "MariaDB 10.6.12"),                           # repositório próprio da MariaDB
    (3306, "MySQL 8.0.34"),
    (80, "nginx/1.22.1"),
])
def test_banner_sem_pacote_exato_nao_e_consultado(port, banner):
    assert osv.package_of(_md(port, banner)) is None


def _greeting(ver: bytes) -> bytes:
    return b"\x4a\x00\x00\x00\x0a" + ver + b"\x00\x11\x22"


def test_handshake_mantem_a_revisao_do_pacote_da_distro():
    d = ports_mod._decode_banner
    assert d(_greeting(b"5.5.5-10.11.6-MariaDB-0+deb12u1")) == "MariaDB 10.11.6-0+deb12u1"
    assert d(_greeting(b"5.5.5-10.6.16-MariaDB-0ubuntu0.22.04.1")) == \
        "MariaDB 10.6.16-0ubuntu0.22.04.1"
    assert d(_greeting(b"8.0.36-0ubuntu0.22.04.1")) == "MySQL 8.0.36-0ubuntu0.22.04.1"
    # sufixos que não são revisão de distro continuam fora do banner
    assert d(_greeting(b"11.4.2-MariaDB-log")) == "MariaDB 11.4.2"
    assert d(_greeting(b"8.0.36-log")) == "MySQL 8.0.36"
    # e o fingerprint segue dando só a versão upstream
    assert ports_mod.fingerprint(3306, "MariaDB 10.11.6-0+deb12u1")["version"] == "10.11.6"


# ── ordem de versões do dpkg ────────────────────────────────────────────────

@pytest.mark.parametrize("a,b,sinal", [
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", 1),
    ("1:9.2p1-2+deb12u10", "1:9.2p1-2+deb12u9", 1),
    ("1:10.11.6-0+deb12u1", "1:10.11.11-0+deb12u1", -1),
    ("1.0~rc1-1", "1.0-1", -1),               # ~ vem antes de tudo
    ("1.0a-1", "1.0+-1", -1),                 # letra antes de símbolo
    ("1.0-1", "1.0-1", 0),
    ("1.0-1", "1.00-1", 0),                   # zeros à esquerda não contam
    ("1:1.0-1", "2.0-1", 1),                  # epoch manda
    ("2.30-1", "2.4-1", 1),
    ("1.0", "1.0-0", 0),
    ("8.0.36-0ubuntu0.22.04.1", "8.0.36-0ubuntu0.22.04.2", -1),
])
def test_comparacao_de_versao_debian(a, b, sinal):
    r = osv.debian_version_cmp(a, b)
    assert (r > 0) - (r < 0) == sinal
    r = osv.debian_version_cmp(b, a)
    assert (r > 0) - (r < 0) == -sinal


def test_corrige_em_e_a_maior_correcao():
    vulns = [{"fixed": "1:9.2p1-2+deb12u3"}, {"fixed": "1:9.2p1-2+deb12u10"},
             {"fixed": None}, {"fixed": "1:9.2p1-2+deb12u2"}]
    assert osv.fixed_in(vulns) == "1:9.2p1-2+deb12u10"
    assert osv.fixed_in([{"fixed": None}]) is None


# ── severidade ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vetor,nota", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_nota_cvss3(vetor, nota):
    assert osv.cvss3_score(vetor) == nota


@pytest.mark.parametrize("vetor", [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",            # v2
    "CVSS:3.1/AV:N/AC:L",                    # incompleto
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
])
def test_vetor_que_nao_e_v3_completo_nao_tem_nota(vetor):
    assert osv.cvss3_score(vetor) is None


def test_severidade_do_registro():
    v3 = {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    assert osv.record_severity({"severity": [{"type": "Ubuntu", "score": "low"}, v3]}) == \
        ("high", 8.1)
    assert osv.record_severity({"severity": [{"type": "Ubuntu", "score": "medium"}]}) == \
        ("medium", None)
    # só CVSS v4: vale a classificação que o registro traz
    v4 = {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}
    assert osv.record_severity({"severity": [v4],
                                "database_specific": {"severity": "CRITICAL"}}) == ("critical", None)
    assert osv.record_severity({"id": "DEBIAN-CVE-2024-1"}) == ("", None)


# ── respostas gravadas do OSV ───────────────────────────────────────────────

_ECO, _PKG = "Debian:12", "openssh"


def _aff(fixed=None, eco=_ECO, name=_PKG):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"package": {"ecosystem": eco, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": events}]}


VULNS = {
    # registro da distro por CVE, sem nota: a nota vem do registro do CVE
    "DEBIAN-CVE-2024-6387": {"id": "DEBIAN-CVE-2024-6387", "upstream": ["CVE-2024-6387"],
                             "affected": [_aff("1:9.2p1-2+deb12u3")]},
    # aviso de segurança do mesmo CVE: junta, não conta duas vezes
    "DSA-5724-1": {"id": "DSA-5724-1", "upstream": ["CVE-2024-6387", "DEBIAN-CVE-2024-6387"],
                   "affected": [_aff("1:9.2p1-2+deb12u3")]},
    "CVE-2024-6387": {"id": "CVE-2024-6387", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
    "DEBIAN-CVE-2023-51385": {"id": "DEBIAN-CVE-2023-51385", "upstream": ["CVE-2023-51385"],
                              "affected": [_aff("1:9.2p1-2+deb12u2")]},
    "CVE-2023-51385": {"id": "CVE-2023-51385", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}]},
    # sem correção publicada na distro: só entra na contagem
    "DEBIAN-CVE-2008-3234": {"id": "DEBIAN-CVE-2008-3234", "upstream": ["CVE-2008-3234"],
                             "affected": [_aff(None)]},
    # retirado pelo OSV: ignorado
    "DEBIAN-CVE-2099-0001": {"id": "DEBIAN-CVE-2099-0001", "withdrawn": "2024-01-01T00:00:00Z",
                             "upstream": ["CVE-2099-0001"], "affected": [_aff("1:9.9")]},
}

# o que o OSV devolve para cada versão do openssh (Debian 12)
AFFECTS = {
    "1:9.2p1-2+deb12u1": ["DEBIAN-CVE-2024-6387", "DSA-5724-1", "DEBIAN-CVE-2023-51385",
                          "DEBIAN-CVE-2008-3234", "DEBIAN-CVE-2099-0001"],
    "1:9.2p1-2+deb12u2": ["DEBIAN-CVE-2024-6387", "DSA-5724-1", "DEBIAN-CVE-2008-3234"],
    "1:9.2p1-2+deb12u3": ["DEBIAN-CVE-2008-3234"],
}


class FakeOSV:
    """OSV de mentira: /v1/querybatch e /v1/vulns/{id}, com contagem e queda."""

    def __init__(self):
        self.down = False
        self.broken_vulns: set[str] = set()
        self.batches: list[dict] = []
        self.gets: list[str] = []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("sem rede", request=request)
        if request.url.path == "/v1/querybatch":
            body = json.loads(request.content)
            self.batches.append(body)
            results = []
            for q in body["queries"]:
                pkg = q["package"]
                ids = (AFFECTS.get(q["version"], [])
                       if (pkg["ecosystem"], pkg["name"]) == (_ECO, _PKG) else [])
                results.append({"vulns": [{"id": i, "modified": "2024-07-01T00:00:00Z"}
                                          for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        vid = request.url.path.rsplit("/", 1)[-1]
        self.gets.append(vid)
        if vid in self.broken_vulns:
            return httpx.Response(503)
        if vid not in VULNS:
            return httpx.Response(404, json={"code": 5, "message": "Bug not found."})
        return httpx.Response(200, json=VULNS[vid])

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class MemCache:
    def __init__(self):
        self.data: dict = {}

    def osv_cache_get(self, eco, pkg, ver, max_age):
        return self.data.get((eco, pkg, ver))

    def osv_cache_put(self, eco, pkg, ver, result):
        self.data[(eco, pkg, ver)] = result


def _pkg(version):
    return osv.Package(_ECO, _PKG, version, "OpenSSH")


def _lookup(fake, cache, pkgs):
    async def run():
        async with httpx.AsyncClient(transport=fake.transport()) as c:
            return await osv.lookup(set(pkgs), cache, c)
    return asyncio.run(run())


def test_lookup_junta_por_cve_e_separa_o_que_nao_tem_correcao():
    fake, cache = FakeOSV(), MemCache()
    pkg = _pkg("1:9.2p1-2+deb12u1")
    res = _lookup(fake, cache, [pkg])[pkg]
    assert [v["id"] for v in res["vulns"]] == ["CVE-2024-6387", "CVE-2023-51385"]
    top = res["vulns"][0]
    assert (top["severity"], top["score"], top["fixed"]) == ("high", 8.1, "1:9.2p1-2+deb12u3")
    assert sorted(top["sources"]) == ["DEBIAN-CVE-2024-6387", "DSA-5724-1"]
    assert res["vulns"][1]["severity"] == "medium"
    assert res["unfixed"] == 1          # CVE-2008-3234; o retirado não conta
    assert len(fake.batches) == 1       # uma consulta em lote
    assert fake.gets.count("CVE-2024-6387") == 1


def test_consulta_leva_so_ecossistema_pacote_e_versao():
    fake = FakeOSV()
    _lookup(fake, MemCache(), [_pkg("1:9.2p1-2+deb12u2")])
    (q,) = fake.batches[0]["queries"]
    assert q == {"package": {"ecosystem": _ECO, "name": _PKG}, "version": "1:9.2p1-2+deb12u2"}
    for req in fake.requests:
        assert req.url.host == "api.osv.dev"
        assert b"acme" not in req.content and "acme" not in str(req.url)


def test_cache_evita_nova_consulta():
    fake, cache = FakeOSV(), MemCache()
    pkg = _pkg("1:9.2p1-2+deb12u2")
    first = _lookup(fake, cache, [pkg])[pkg]
    fake.down = True                    # com cache, nem precisa de rede
    assert _lookup(fake, cache, [pkg])[pkg] == first
    assert len(fake.batches) == 1


def test_falha_de_rede_ou_de_um_registro_e_inconclusivo():
    fake, cache = FakeOSV(), MemCache()
    pkg = _pkg("1:9.2p1-2+deb12u1")
    fake.down = True
    assert _lookup(fake, cache, [pkg]) == {pkg: None}
    fake.down = False
    fake.broken_vulns = {"DSA-5724-1"}
    assert _lookup(fake, cache, [pkg]) == {pkg: None}
    assert cache.data == {}             # nada de resultado parcial no cache


def test_versao_sem_cve_corrigivel_nao_gera_vuln():
    fake = FakeOSV()
    pkg = _pkg("1:9.2p1-2+deb12u3")
    res = _lookup(fake, MemCache(), [pkg])[pkg]
    assert res == {"vulns": [], "unfixed": 1}


def test_usn_so_complementa_o_registro_do_ubuntu():
    """Um USN cita os CVEs de todas as versões do aviso: o CVE-2025-26466 não
    existe no 22.04 (não há UBUNTU-CVE para ele aqui), mas está no USN-7270-1."""
    eco = "Ubuntu:22.04:LTS"
    pkg = osv.Package(eco, "openssh", "1:8.9p1-3ubuntu0.10", "OpenSSH", True)
    recs = [
        {"id": "USN-7270-1",
         "upstream": ["CVE-2025-26465", "CVE-2025-26466",
                      "UBUNTU-CVE-2025-26465", "UBUNTU-CVE-2025-26466"],
         "related": ["UBUNTU-CVE-2025-26465", "UBUNTU-CVE-2025-26466"],
         "affected": [_aff("1:8.9p1-3ubuntu0.11", eco=eco)]},
        {"id": "UBUNTU-CVE-2025-26465", "upstream": ["CVE-2025-26465"],
         "related": ["USN-7270-1"],
         "severity": [{"type": "CVSS_V3",
                       "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"},
                      {"type": "Ubuntu", "score": "medium"}],
         "affected": [_aff("1:8.9p1-3ubuntu0.11", eco=eco)]},
    ]
    res = osv.assess_package(pkg, recs)
    assert [v["id"] for v in res["vulns"]] == ["CVE-2025-26465"]
    assert sorted(res["vulns"][0]["sources"]) == ["UBUNTU-CVE-2025-26465", "USN-7270-1"]
    assert res["vulns"][0]["severity"] == "medium" and res["unfixed"] == 0


def test_dla_conta_no_debian_lts():
    """O Debian 11 (LTS) não tem DEBIAN-CVE: os CVEs só vêm nos DLA."""
    eco = "Debian:11"
    pkg = osv.Package(eco, "openssh", "1:8.4p1-5+deb11u3", "OpenSSH")
    recs = [{"id": "DLA-4057-1", "upstream": ["CVE-2025-26465", "DEBIAN-CVE-2025-26465"],
             "affected": [_aff("1:8.4p1-5+deb11u4", eco=eco)]}]
    res = osv.assess_package(pkg, recs)
    assert [(v["id"], v["fixed"]) for v in res["vulns"]] == [("CVE-2025-26465",
                                                               "1:8.4p1-5+deb11u4")]


def test_correcao_de_outro_ecossistema_nao_conta():
    rec = {"id": "DEBIAN-CVE-2024-6387", "upstream": ["CVE-2024-6387"],
           "affected": [_aff("1:9.2p1-2+deb12u3", eco="Debian:11")]}
    res = osv.assess_package(_pkg("1:9.2p1-2+deb12u2"), [rec])
    assert res == {"vulns": [], "unfixed": 1}


# ── cache no SQLite ─────────────────────────────────────────────────────────

def test_cache_sqlite_validade_e_limpeza(tmp_path):
    s = Storage(str(tmp_path / "padme.db"))
    data = {"vulns": [{"id": "CVE-2024-6387"}], "unfixed": 0}
    s.osv_cache_put(_ECO, _PKG, "v1", data, now=1000.0)
    assert s.osv_cache_get(_ECO, _PKG, "v1", max_age=3600, now=1000.0 + 3600) == data
    assert s.osv_cache_get(_ECO, _PKG, "v1", max_age=3600, now=1000.0 + 3601) is None
    assert s.osv_cache_get(_ECO, _PKG, "outra", max_age=3600, now=1000.0) is None
    s.osv_cache_put(_ECO, _PKG, "v2", data, now=1000.0 + 8 * 86400)  # limpa as velhas
    assert s.osv_cache_get(_ECO, _PKG, "v1", max_age=1e9, now=1000.0) is None
    s.close()


def test_banco_antigo_ganha_a_tabela_de_cache(tmp_path):
    db = str(tmp_path / "padme.db")
    Storage(db).close()
    conn = sqlite3.connect(db)
    conn.execute("DROP TABLE osv_cache")      # banco de uma versão anterior
    conn.commit()
    conn.close()
    s = Storage(db)
    s.osv_cache_put(_ECO, _PKG, "v1", {"vulns": [], "unfixed": 0})
    assert s.osv_cache_get(_ECO, _PKG, "v1", max_age=60) == {"vulns": [], "unfixed": 0}
    s.close()
    Storage(db, readonly=True).close()        # o painel continua abrindo o banco


# ── engine: estado, escopo e eventos ────────────────────────────────────────

HOST = "203.0.113.7"
KEY = f"{HOST}:22"


@pytest.fixture
def cenario(monkeypatch, tmp_path):
    estado = {"banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", "ok": True, "open": True}

    async def portas(host, ports, timeout, banner=True, pace=None, limit=None):
        recs = []
        if estado["open"]:
            b = estado["banner"]
            recs = [Record(Kind.PORT, f"{host}:22", f"open · {b}", metadata=_md(22, b))]
        return CollectionResult(records=recs, ok=estado["ok"])

    async def ptr(ip, timeout):
        return CollectionResult(records=[], ok=True)

    monkeypatch.setattr(engine_mod.ports, "collect_host", portas)
    monkeypatch.setattr(engine_mod.dns, "collect_ptr", ptr)
    db = str(tmp_path / "padme.db")
    cfg = Config(targets=[HOST], db_path=db)
    cfg.collectors.ports = True
    cfg.collectors.http = cfg.collectors.tls = cfg.collectors.favicon = False
    cfg.network.allow_private_ips = True
    storage = Storage(db)
    eng = Engine(cfg, storage)
    fake = FakeOSV()
    eng._osv_transport = fake.transport()
    yield eng, storage, estado, fake
    storage.close()


def _scan(eng):
    result = asyncio.run(eng.scan_target(HOST))
    return result, eng.apply(result)


def _cve_events(events):
    return [e for e in events if e.kind == Kind.VULN]   # a troca de banner gera o da porta


def _vuln(storage):
    rows = [r for r in storage.all_state([HOST]) if r["kind"] == "vuln"]
    return rows[0] if rows else None


def test_engine_cve_ciclo_completo(cenario):
    eng, storage, estado, fake = cenario

    # 1. baseline: o CVE entra no estado e vira problema, sem evento
    _, events = _scan(eng)
    assert events == []
    row = _vuln(storage)
    assert row["key"] == KEY
    assert row["value"] == ("openssh 1:9.2p1-2+deb12u2 · CVE-2024-6387 (high 8.1)"
                            " · corrige em 1:9.2p1-2+deb12u3")
    md = row["metadata"]
    assert md["cves"] == ["CVE-2024-6387"] and md["unfixed"] == 1
    assert md["fixed_in"] == "1:9.2p1-2+deb12u3"
    assert md["confidence"] == "high" and md["port"] == 22
    (f,) = [f for f in derive(HOST, {"vuln": [row]})]
    assert (f["kind"], f["severity"], f["who"]) == ("CVE", "high", KEY)

    # 2. versão nova e OSV fora do ar: inconclusivo, o CVE anterior fica
    estado["banner"] = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1"
    fake.down = True
    result, events = _scan(eng)
    assert _cve_events(events) == [] and _vuln(storage)["value"] == row["value"]
    assert result.collector_stats["osv"] == {"ok": 0, "fail": 1}
    assert result.complete            # consultivo: não deixa a coleta parcial

    # 3. OSV de volta: a versão pior ganhou um CVE -> CHANGED pelo CVE novo
    fake.down = False
    _, events = _scan(eng)
    (e,) = _cve_events(events)
    assert (e.kind, e.event_type) == (Kind.VULN, EventType.CHANGED)
    assert e.new_value == ("openssh 1:9.2p1-2+deb12u1 · 2 CVEs, o pior CVE-2024-6387 "
                           "(high 8.1) · corrige em 1:9.2p1-2+deb12u3")
    ra = assess(e)
    assert ra.level == Level.MEDIUM   # o CVE novo (CVE-2023-51385) é medium
    assert "KNOWN_VULNERABLE_VERSION" in ra.reasons

    # 4. pacote corrigido: o problema sai como resolvido
    estado["banner"] = _SSH_DEB12
    _, events = _scan(eng)
    (e,) = _cve_events(events)
    assert (e.kind, e.event_type) == (Kind.VULN, EventType.REMOVED)
    assert assess(e).level == Level.LOW and "ISSUE_RESOLVED" in assess(e).reasons
    assert _vuln(storage) is None
    assert len(fake.batches) == 3     # uma consulta por scan com versão nova


def test_engine_preserva_sem_prova(cenario):
    eng, storage, estado, fake = cenario
    _scan(eng)
    before = _vuln(storage)["value"]

    # port-scan inconclusivo: nada sai
    estado["ok"] = False
    assert _scan(eng)[1] == [] and _vuln(storage)["value"] == before

    # porta aberta, mas o banner parou de mostrar a versão: sumir não é correção
    estado["ok"], estado["banner"] = True, "SSH-2.0-OpenSSH_9.2p1"
    events = _scan(eng)[1]
    assert [e.kind for e in events] == [Kind.PORT]     # só a mudança de banner
    assert _vuln(storage)["value"] == before

    # porta fechou (observado): o CVE sai junto
    estado["open"] = False
    events = _scan(eng)[1]
    assert {(e.kind, e.event_type) for e in events} == {
        (Kind.PORT, EventType.REMOVED), (Kind.VULN, EventType.REMOVED)}


def test_engine_sem_ports_ou_sem_osv_nao_consulta(cenario):
    eng, storage, estado, fake = cenario
    eng.cfg.collectors.osv = False
    _scan(eng)
    assert fake.requests == [] and _vuln(storage) is None


def test_cve_novo_numa_versao_ja_vista_vira_added_pelo_pior(cenario):
    eng, storage, estado, fake = cenario
    estado["banner"] = _SSH_DEB12            # baseline sem CVE corrigível
    _scan(eng)
    assert _vuln(storage) is None
    estado["banner"] = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"
    (e,) = _cve_events(_scan(eng)[1])
    assert e.event_type == EventType.ADDED
    ra = assess(e)
    assert ra.level == Level.HIGH and ra.confidence == Confidence.HIGH
    assert ra.rule_id == "known-cve"


# ── risco, escopo e evidência ───────────────────────────────────────────────

def _ev(event_type, md, key=KEY):
    return Event(HOST, event_type, Kind.VULN, key, "antes", "depois", metadata=md)


def test_risco_do_cve():
    crit = {"vulns": [{"id": "CVE-1", "severity": "critical"}], "confidence": "medium"}
    ra = assess(_ev(EventType.ADDED, crit))
    assert ra.level == Level.CRITICAL and ra.confidence == Confidence.MEDIUM
    # sem nota conhecida: medium
    assert assess(_ev(EventType.ADDED, {"vulns": [{"id": "CVE-1", "severity": "unknown"}]})
                  ).level == Level.MEDIUM
    # a lista só diminuiu (atualização corrigiu parte): baixo
    menos = {"vulns": [{"id": "CVE-1", "severity": "high"}],
             "_changes": {"cves": {"old": ["CVE-1", "CVE-2"], "new": ["CVE-1"]},
                          "version": {"old": "a", "new": "b"}}}
    assert assess(_ev(EventType.CHANGED, menos)).level == Level.LOW
    # nota reavaliada para cima
    subiu = {"vulns": [{"id": "CVE-1", "severity": "critical"}],
             "_changes": {"max_severity": {"old": "high", "new": "critical"}}}
    assert assess(_ev(EventType.CHANGED, subiu)).level == Level.CRITICAL


def test_escopo_e_evidencia_do_cve():
    assert scope_of(Kind.VULN, KEY, HOST) == ("vuln", HOST)
    assert scope_of(Kind.VULN, "2001:db8::1:22", "2001:db8::1") == ("vuln", "2001:db8::1")
    md = {"package": "openssh", "ecosystem": _ECO, "version": "1:9.2p1-2+deb12u2",
          "cves": ["CVE-2024-6387"], "max_severity": "high", "max_score": 8.1,
          "confidence": "high"}
    ev = evidence_of(Kind.VULN, KEY, "x", md)
    assert ev["type"] == "osv_lookup" and ev["cves"] == ["CVE-2024-6387"]
