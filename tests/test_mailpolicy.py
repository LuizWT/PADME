"""SPF efetivo (include/redirect/limite de consultas), DMARC pct/t e a
integração com collector, risco e diff."""

import asyncio

import dns.exception
import dns.resolver
import pytest

from padme import risk as L
from padme.collectors import dnsrecon
from padme.differ import field_changes
from padme.mailpolicy import SpfInconclusive, findings, spf_effective
from padme.models import Event, EventType, Kind
from padme.risk import Level, assess


def _eval(record, zone):
    """zone: domínio -> lista de TXT SPF | 'TIMEOUT'."""
    async def fetch(domain):
        v = zone.get(domain, [])
        if v == "TIMEOUT":
            raise SpfInconclusive(domain)
        return v
    return asyncio.run(spf_effective(record, fetch))


# ── avaliação ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("record,zone,result,via", [
    ("v=spf1 mx -all", {}, "-", "all"),
    ("v=spf1 include:ok.net -all", {"ok.net": ["v=spf1 ip4:1.2.3.0/24 ~all"]}, "-", "all"),
    # incluído que passa qualquer um: o include casa o IP do atacante
    ("v=spf1 include:evil.net -all", {"evil.net": ["v=spf1 +all"]},
     "+", "include:evil.net → all"),
    ("v=spf1 include:a.net -all", {"a.net": ["v=spf1 include:b.net"], "b.net": ["v=spf1 all"]},
     "+", "include:a.net → include:b.net → all"),
    # qualificador do include vale: -include de algo que passa tudo = fail
    ("v=spf1 -include:evil.net +all", {"evil.net": ["v=spf1 +all"]},
     "-", "include:evil.net → all"),
    # incluído neutro/softfail NÃO casa: segue para o próximo termo
    ("v=spf1 include:n.net -all", {"n.net": ["v=spf1 ?all"]}, "-", "all"),
    ("v=spf1 include:ok.net", {"ok.net": ["v=spf1 -all"]}, "?", "sem all (padrão neutro)"),
    ("v=spf1 redirect=_spf.x.com", {"_spf.x.com": ["v=spf1 -all"]},
     "-", "redirect:_spf.x.com → all"),
    ("v=spf1 redirect=_spf.x.com", {"_spf.x.com": ["v=spf1 +all"]},
     "+", "redirect:_spf.x.com → all"),
    # redirect é ignorado quando há `all` (RFC 7208 §6.1)
    ("v=spf1 -all redirect=evil.net", {"evil.net": ["v=spf1 +all"]}, "-", "all"),
    ("v=spf1 ip4:0.0.0.0/0 -all", {}, "+", "ip4:0.0.0.0/0 (4.294.967.296 endereços)"),
    ("v=spf1 ip4:52.0.0.0/8 -all", {}, "+", "ip4:52.0.0.0/8 (16.777.216 endereços)"),
    ("v=spf1 ip4:52.1.0.0/16 -all", {}, "-", "all"),
    ("v=spf1 ip6:::/0 -all", {}, "+", None),
    ("v=spf1 ?ip4:0.0.0.0/1 -all", {}, "?", None),
    # macro depende do remetente: conta a consulta, não segue, não quebra
    ("v=spf1 include:%{i}._spf.x.com -all", {}, "-", "all"),
])
def test_spf_efetivo(record, zone, result, via):
    v = _eval(record, zone)
    assert v.result == result
    if via is not None:
        assert v.via == via


@pytest.mark.parametrize("record,zone,motivo", [
    ("v=spf1 a mx a mx a mx a mx a mx a -all", {}, "mais de 10"),
    ("v=spf1 include:sem.net -all", {}, "sem.net sem registro SPF"),
    ("v=spf1 include:dois.net -all", {"dois.net": ["v=spf1 -all", "v=spf1 +all"]},
     "2 registros SPF"),
    ("v=spf1 ip4:999.1.1.1 -all", {}, "inválido"),
    ("v=spf1 foo:bar -all", {}, "mecanismo desconhecido"),
    # laço a -> b -> a termina pelo limite de consultas
    ("v=spf1 include:a.net -all", {"a.net": ["v=spf1 include:b.net"],
                                   "b.net": ["v=spf1 include:a.net"]}, "mais de 10"),
])
def test_spf_permerror(record, zone, motivo):
    v = _eval(record, zone)
    assert v.result == "permerror" and motivo in v.via


def test_spf_consulta_sem_resposta_e_inconclusiva():
    with pytest.raises(SpfInconclusive):
        _eval("v=spf1 include:lento.net -all", {"lento.net": "TIMEOUT"})


def test_valor_estavel_e_legivel():
    v = _eval("v=spf1 include:evil.net -all", {"evil.net": ["v=spf1 +all"]})
    assert v.value == "+all · include:evil.net → all" and v.lookups == 1


# ── DMARC ───────────────────────────────────────────────────────────────────
def _codes(value, md=None):
    return [(f.code, f.high) for f in findings("x.com|DMARC", value, md)]


def test_dmarc_pct_e_modo_teste():
    # quarentena parcial: o resto fica SEM política -> grave
    assert _codes("v=DMARC1; p=quarantine; pct=50") == [(L.DMARC_PARTIAL, True)]
    # rejeição parcial: o resto vai para quarentena -> anota, não escala
    assert _codes("v=DMARC1; p=reject; pct=25") == [(L.DMARC_PARTIAL, False)]
    assert _codes("v=DMARC1; p=quarantine; t=y") == [(L.DMARC_PARTIAL, True)]
    assert _codes("v=DMARC1; p=reject; pct=100") == []
    assert _codes("v=DMARC1; p=reject") == []


def test_dmarc_invalido_ou_duplicado_nao_protege():
    assert _codes("v=DMARC1; rua=mailto:x@x.com") == [(L.DMARC_NOT_ENFORCED, True)]
    assert _codes("v=DMARC1; p=reject | v=DMARC1; p=none", {"records": 2}) == \
        [(L.DMARC_NOT_ENFORCED, True)]


def test_dmarc_reject_parcial_nao_eleva_nivel():
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, "x.com|DMARC",
              old_value="v=DMARC1; p=reject", new_value="v=DMARC1; p=reject; pct=25")
    a = assess(e)
    assert L.DMARC_PARTIAL in a.reasons and a.level == a.base


# ── risco / diff ────────────────────────────────────────────────────────────
def test_remocao_do_spf_nao_gera_dois_alertas_graves():
    raw = Event("x.com", EventType.REMOVED, Kind.MAILSEC, "x.com|SPF", "v=spf1 -all", None)
    eff = Event("x.com", EventType.REMOVED, Kind.MAILSEC, "x.com|SPF-EFFECTIVE",
                "-all · all", None)
    assert assess(raw).level == Level.HIGH and L.MAIL_PROTECTION_REMOVED in assess(raw).reasons
    assert assess(eff).level == Level.LOW and not assess(eff).reasons


def test_permerror_eleva_high():
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, "x.com|SPF-EFFECTIVE",
              "-all · all", "permerror · mais de 10 consultas DNS (RFC 7208 §4.6.4)",
              metadata={"result": "permerror", "via": "mais de 10 consultas DNS"})
    a = assess(e)
    assert a.level == Level.HIGH and L.SPF_PERMERROR in a.reasons


def test_diff_por_campo_mostra_resultado_efetivo():
    ch = field_changes(Kind.MAILSEC, "-all · all", {"result": "-", "via": "all"},
                       "+all · include:evil.net → all",
                       {"result": "+", "via": "include:evil.net → all"})
    assert ch["result"] == {"old": "-", "new": "+"}


# ── collector ───────────────────────────────────────────────────────────────
class _TXT:
    def __init__(self, s):
        self.strings = [s.encode()]


def _resolver(script):
    class _R:
        lifetime = 0.0

        async def resolve(self, name, rtype):
            v = script.get((name, rtype), "NX")
            if v == "NX":
                raise dns.resolver.NXDOMAIN
            if v == "TIMEOUT":
                raise dns.exception.Timeout
            return [_TXT(t) for t in v] if rtype == "TXT" else v
    return _R


def _collect(monkeypatch, script):
    monkeypatch.setattr(dnsrecon.dns.asyncresolver, "Resolver", _resolver(script))
    cr = asyncio.run(dnsrecon.collect("alvo.com", 5))
    return cr, {r.key: r for r in cr.records if r.kind == Kind.MAILSEC}


def test_collector_segue_include_ate_o_mais_all(monkeypatch):
    cr, mail = _collect(monkeypatch, {
        ("alvo.com", "TXT"): ["v=spf1 include:vendor.net -all"],
        ("vendor.net", "TXT"): ["google-site-verification=x", "v=spf1 +all"],
        ("_dmarc.alvo.com", "TXT"): ["v=DMARC1; p=quarantine; pct=20; t=y"],
    })
    assert cr.ok
    eff = mail["alvo.com|SPF-EFFECTIVE"]
    assert eff.value == "+all · include:vendor.net → all"
    assert eff.metadata["result"] == "+" and eff.metadata["lookups"] == 1
    # o TXT do apex é o mesmo de antes: só o efetivo denuncia a mudança
    assert mail["alvo.com|SPF"].value == "v=spf1 include:vendor.net -all"
    assert mail["alvo.com|DMARC"].metadata["pct"] == "20"
    assert mail["alvo.com|DMARC"].metadata["t"] == "y"


def test_collector_include_sem_resposta_preserva(monkeypatch):
    cr, mail = _collect(monkeypatch, {
        ("alvo.com", "TXT"): ["v=spf1 include:lento.net -all"],
        ("lento.net", "TXT"): "TIMEOUT",
    })
    assert cr.ok is False                       # nada vira REMOVED neste ciclo
    assert "alvo.com|SPF" in mail and "alvo.com|SPF-EFFECTIVE" not in mail


def test_collector_dois_spf_no_apex_e_permerror_estavel(monkeypatch):
    cr, mail = _collect(monkeypatch, {
        ("alvo.com", "TXT"): ["v=spf1 -all", "v=spf1 include:x.net ~all"],
    })
    raw = mail["alvo.com|SPF"].value
    assert raw == "v=spf1 -all | v=spf1 include:x.net ~all"   # ordenado: não oscila
    assert mail["alvo.com|SPF-EFFECTIVE"].metadata["result"] == "permerror"


def test_notificacao_do_spf_efetivo_nao_parece_boa_noticia():
    from padme.notify.formatting import desc
    e = Event("x.com", EventType.ADDED, Kind.MAILSEC, "x.com|SPF-EFFECTIVE",
              new_value="+all · include:evil.net → all")
    assert "adicionada" not in desc(e) and "SPF efetivo" in desc(e)
    raw = Event("x.com", EventType.REMOVED, Kind.MAILSEC, "x.com|SPF", "v=spf1 -all", None)
    assert "REMOVIDA" in desc(raw)


def test_ponta_a_ponta_include_vira_mais_all(monkeypatch, tmp_path):
    """TXT do apex idêntico nos dois scans; só o fornecedor incluído afrouxou.
    Tem de sair exatamente UM evento: o SPF efetivo mudou, grave, com o diff."""
    from padme.storage import Storage

    zone = {("alvo.com", "TXT"): ["v=spf1 include:vendor.net -all"],
            ("vendor.net", "TXT"): ["v=spf1 ip4:203.0.113.0/24 ~all"]}
    scope = {(Kind.MAILSEC.value, "alvo.com")}
    st = Storage(tmp_path / "p.db")
    try:
        _, before = _collect(monkeypatch, zone)
        st.apply_scan("alvo.com", list(before.values()), scope)       # baseline
        zone[("vendor.net", "TXT")] = ["v=spf1 +all"]
        _, after = _collect(monkeypatch, zone)
        events = st.apply_scan("alvo.com", list(after.values()), scope)
    finally:
        st.close()
    assert [(e.event_type, e.key) for e in events] == \
        [(EventType.CHANGED, "alvo.com|SPF-EFFECTIVE")]
    a = assess(events[0])
    assert a.level == Level.HIGH and L.SPF_PERMISSIVE in a.reasons
    assert events[0].new_value == "+all · include:vendor.net → all"
    # antes: o ~all do fornecedor não casa o atacante -> cai no -all do apex
    assert events[0].metadata["_changes"]["result"] == {"old": "-", "new": "+"}
