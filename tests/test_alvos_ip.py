"""Alvos por IP e faixa (CIDR): normalização, teto de hosts, regras de rede,
coletores certos para cada tipo de alvo e nomes descobertos só registrados.

Os IPs dos testes são de documentação (203.0.113.0/24, 2001:db8::/32), que não
são públicos: os testes que montam um config ligam `allow_private_ips`."""

import asyncio

import httpx
import pytest

from padme import engine as engine_mod
from padme import initcfg, targets
from padme.collectors import dns as dns_mod
from padme.collectors import http as http_mod
from padme.config import Config, _normalize_target
from padme.engine import Engine
from padme.models import CollectionResult, Kind, Record, scope_of
from padme.storage import Storage
from padme.web.overview import _stat_tiles


# ── normalização ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("entrada, esperado", [
    ("203.0.113.7", "203.0.113.7"),
    ("https://203.0.113.7:8443/painel", "203.0.113.7"),
    ("203.0.113.7:443", "203.0.113.7"),
    ("203.0.113.0/28", "203.0.113.0/28"),
    ("203.0.113.5/32", "203.0.113.5"),            # /32 é um IP só
    ("2001:DB8::1", "2001:db8::1"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("2001:db8::/120", "2001:db8::/120"),
    ("Exemplo.COM", "exemplo.com"),                # domínio segue como antes
])
def test_normaliza_ip_faixa_e_dominio(entrada, esperado):
    assert _normalize_target(entrada) == esperado


@pytest.mark.parametrize("entrada, trecho", [
    ("10.0.0.5/24", "use 10.0.0.0/24"),            # bits de host: diz a forma certa
    ("999.1.1.1", "IP inválido"),
    ("203.0.113.0/33", "faixa inválida"),
    ("1.2.3", "alvo inválido"),                    # TLD só de número não é domínio
])
def test_recusa_ip_ou_faixa_invalidos(entrada, trecho):
    with pytest.raises(ValueError, match=trecho):
        _normalize_target(entrada)


def test_tipo_e_expansao():
    assert targets.kind_of("acme.com") == "domain"
    assert targets.kind_of("203.0.113.7") == "ip"
    assert targets.kind_of("203.0.113.0/30") == "net"
    assert targets.hosts_of("203.0.113.0/30") == ["203.0.113.1", "203.0.113.2"]
    assert targets.hosts_of("203.0.113.0/31") == ["203.0.113.0", "203.0.113.1"]
    assert targets.hosts_of("203.0.113.7") == ["203.0.113.7"]
    assert targets.host_count("203.0.113.0/24") == 254
    assert targets.host_count("2001:db8::/64") == 2 ** 64   # conta sem expandir
    assert targets.url_host("2001:db8::1") == "[2001:db8::1]"
    assert targets.url_host("203.0.113.7") == "203.0.113.7"


# ── config ───────────────────────────────────────────────────────────────────
def _yaml(tmp_path, alvos, extra=""):
    p = tmp_path / "config.yaml"
    linhas = "\n".join(f"  - {a}" for a in alvos)
    p.write_text(f"scope_confirmed: true\ntargets:\n{linhas}\n{extra}", encoding="utf-8")
    return p


def test_config_aceita_dominio_ip_e_faixa_juntos(tmp_path):
    cfg = Config.load(_yaml(tmp_path, ["acme.com", "203.0.113.0/28", "203.0.113.200"],
                            "network:\n  allow_private_ips: true\n"))
    assert cfg.targets == ["acme.com", "203.0.113.0/28", "203.0.113.200"]
    assert cfg.collectors.max_hosts_per_target == 256


def test_config_recusa_faixa_acima_do_teto(tmp_path):
    with pytest.raises(ValueError, match="65534 hosts, acima do teto de 256"):
        Config.load(_yaml(tmp_path, ["8.8.0.0/16"]))
    cfg = Config.load(_yaml(tmp_path, ["8.8.0.0/16"],
                            "collectors:\n  max_hosts_per_target: 70000\n"))
    assert cfg.targets == ["8.8.0.0/16"]


def test_config_recusa_faixa_so_privada_sem_allow_private(tmp_path):
    with pytest.raises(ValueError, match="privados ou reservados"):
        Config.load(_yaml(tmp_path, ["10.0.0.0/30"]))
    cfg = Config.load(_yaml(tmp_path, ["10.0.0.0/30"],
                            "network:\n  allow_private_ips: true\n"))
    assert cfg.targets == ["10.0.0.0/30"]


# ── engine: só os coletores de host, com PTR no lugar do DNS ─────────────────
def _nao_pode(nome):
    async def falha(*a, **k):
        raise AssertionError(f"{nome} não roda em alvo IP")
    return falha


@pytest.fixture
def engine_ip(monkeypatch, tmp_path):
    for mod, fn in ((engine_mod.subdomains, "collect"), (engine_mod.wildcard, "detect"),
                    (engine_mod.dnsrecon, "collect"), (engine_mod.passive, "collect"),
                    (engine_mod.takeover, "collect_host"), (engine_mod.dns, "collect_host")):
        monkeypatch.setattr(mod, fn, _nao_pode(f"{mod.__name__}.{fn}"))
    estado = {"ports_ok": True}

    async def ptr(ip, timeout):
        recs = [dns_mod.dns_record(ip, "PTR", ["vpn.acme.com"])] if ip.endswith(".1") else []
        return CollectionResult(records=recs, ok=True)

    async def portas(host, ports, timeout, banner=True, pace=None, limit=None):
        recs = [Record(Kind.PORT, f"{host}:22", "open", metadata={"port": 22})] \
            if host.endswith(".1") else []
        return CollectionResult(records=recs, ok=estado["ports_ok"])

    async def web(host, client, *a, **k):
        recs = [Record(Kind.HTTP, f"https://{host}", "200 | nginx | ")] \
            if host.endswith(".2") else []
        return CollectionResult(records=recs, ok=True)

    async def tls(host, timeout, **k):
        return CollectionResult(records=[], ok=True)

    monkeypatch.setattr(engine_mod.dns, "collect_ptr", ptr)
    monkeypatch.setattr(engine_mod.ports, "collect_host", portas)
    monkeypatch.setattr(engine_mod.http, "collect_host", web)
    monkeypatch.setattr(engine_mod.tls, "collect_host", tls)
    db = str(tmp_path / "padme.db")
    cfg = Config(targets=["203.0.113.0/30"], db_path=db)
    cfg.collectors.ports = True
    cfg.collectors.favicon = False
    cfg.network.allow_private_ips = True
    storage = Storage(db)
    yield Engine(cfg, storage), estado
    storage.close()


def test_alvo_ip_roda_so_coletores_de_host(engine_ip):
    eng, _ = engine_ip
    res = asyncio.run(eng.scan_target("203.0.113.0/30"))
    chaves = {(r.kind, r.key) for r in res.records}
    assert chaves == {(Kind.DNS, "203.0.113.1|PTR"), (Kind.PORT, "203.0.113.1:22"),
                      (Kind.HTTP, "https://203.0.113.2")}
    for ip in ("203.0.113.1", "203.0.113.2"):
        assert ("port", ip) in res.observed_scopes and ("dns", ip) in res.observed_scopes
    assert not any(r.kind == Kind.SUBDOMAIN for r in res.records)


def test_nome_do_ptr_so_e_registrado(engine_ip):
    eng, _ = engine_ip
    res = asyncio.run(eng.scan_target("203.0.113.0/30"))
    ptr = next(r for r in res.records if r.key.endswith("|PTR"))
    assert ptr.value == "vpn.acme.com"
    # o nome não virou host sondado: só os 2 IPs da faixa passaram pelos coletores
    sondados = {host for (escopo, host) in res.observed_scopes}
    assert sondados == {"203.0.113.1", "203.0.113.2"}
    assert "vpn.acme.com" not in sondados


def test_porta_so_sai_com_prova(engine_ip):
    eng, estado = engine_ip
    eng.apply(asyncio.run(eng.scan_target("203.0.113.0/30")))           # baseline
    estado["ports_ok"] = False                                           # varredura inconclusiva
    eventos = eng.apply(asyncio.run(eng.scan_target("203.0.113.0/30")))
    assert not [e for e in eventos if e.kind == Kind.PORT]               # nada "removido"
    assert ("port", "203.0.113.1:22") in {(k, key) for (k, key) in eng.storage.load_state(
        "203.0.113.0/30")}


# ── coletores ────────────────────────────────────────────────────────────────
def test_ptr_nxdomain_e_timeout(monkeypatch):
    import dns.resolver

    class Resposta(list):
        pass

    class R:
        lifetime = 0

        async def resolve(self, nome, tipo):
            assert tipo == "PTR" and str(nome).endswith("in-addr.arpa.")
            if "7.113" in str(nome):
                raise dns.resolver.NXDOMAIN()
            if "8.113" in str(nome):
                raise TimeoutError()

            class Rr:
                def to_text(self):
                    return "Host.Exemplo.com."
            return Resposta([Rr()])

    monkeypatch.setattr(dns_mod.dns.asyncresolver, "Resolver", R)
    ok = asyncio.run(dns_mod.collect_ptr("203.0.113.6", 2.0))
    assert ok.ok and ok.records[0].key == "203.0.113.6|PTR" and ok.records[0].value == "host.exemplo.com"
    sem = asyncio.run(dns_mod.collect_ptr("203.0.113.7", 2.0))
    assert sem.ok and sem.records == []                                  # sem PTR: autoritativo
    lento = asyncio.run(dns_mod.collect_ptr("203.0.113.8", 2.0))
    assert not lento.ok                                                  # preserva


def test_http_em_ipv6_usa_colchetes_e_o_escopo_bate(monkeypatch):
    pedidos = []

    def responde(req):
        pedidos.append(str(req.url))
        return httpx.Response(200, headers={"server": "nginx"}, text="ok")

    async def roda():
        async with httpx.AsyncClient(transport=httpx.MockTransport(responde)) as c:
            return await http_mod.collect_host("2001:db8::1", c, allow_private=True)

    res = asyncio.run(roda())
    assert pedidos[0] == "https://[2001:db8::1]"
    http_rec = next(r for r in res.records if r.kind == Kind.HTTP)
    assert scope_of(Kind.HTTP, http_rec.key, "2001:db8::/120") == ("http", "2001:db8::1")


# ── painel, init e doctor ────────────────────────────────────────────────────
def test_painel_mostra_hosts_no_alvo_ip():
    kinds = {"port": [{"key": "203.0.113.1:22", "value": "open"},
                      {"key": "203.0.113.1:443", "value": "open"}],
             "http": [{"key": "https://203.0.113.2", "value": "200"}]}
    html = _stat_tiles(kinds, "203.0.113.0/30")
    assert "hosts respondendo" in html and ">2<" in html and "de 2 na faixa" in html
    assert "subdomínios" not in html
    assert "subdomínios" in _stat_tiles(kinds, "acme.com")               # domínio: como antes


def test_init_com_ip_avisa_das_portas(tmp_path, capsys):
    cfg = tmp_path / "config.yaml"
    assert initcfg.run(cfg, targets=["8.8.8.8"], yes=True) == 0
    assert "Aviso: sem a varredura de portas" in capsys.readouterr().out


def test_init_com_faixa_privada_nao_cria_config(tmp_path, capsys):
    cfg = tmp_path / "config.yaml"
    assert initcfg.run(cfg, targets=["10.0.0.0/30"], yes=True) == 2
    assert not cfg.exists()
    assert "allow_private_ips" in capsys.readouterr().err


def test_doctor_estima_conexoes_do_alvo_ip(tmp_path, capsys, monkeypatch):
    from padme.cli import _cmd_doctor

    async def sem_rede(cfg, timeout=5.0):
        return []

    monkeypatch.setattr("padme.cli.netcheck.run", sem_rede)
    cfg = Config(targets=["203.0.113.0/30"], db_path=str(tmp_path / "padme.db"))
    cfg.collectors.ports = True
    asyncio.run(_cmd_doctor(cfg, None))
    out = capsys.readouterr().out
    n = len(cfg.collectors.ports_list)
    assert f"alvo IP: 2 host(s) × {n} porta(s) = {2 * n} conexões por ciclo" in out
