"""Risk engine: severidade + confiança + reason codes + regras contextuais.

Determinístico e explicável: cada elevação tem uma regra nomeada e códigos de
razão; sem contexto aplicável, fica na base (compat total). Inclui casos que NÃO
devem disparar.
"""

from padme import risk as L
from padme.models import Event, EventType, Kind
from padme.risk import Confidence, Level, assess, severity


def _port(port, etype=EventType.ADDED, meta=None, ctx=None):
    md = dict(meta or {"port": port})
    if ctx is not None:
        md["_context"] = ctx
    return Event("x.com", etype, Kind.PORT, f"x.com:{port}", new_value="open", metadata=md)


# ── base (sem contexto) ──────────────────────────────────────────────────────
def test_porta_comum_nova_base_high_com_codigo():
    r = assess(_port(443))
    assert r.level == Level.HIGH and r.base == Level.HIGH
    assert r.reasons == [L.NEW_OPEN_PORT]          # explica, sem elevar
    assert r.rule_id is None
    assert r.confidence == Confidence.CONFIRMED


def test_porta_rdp_nova_critical_com_reason_codes():
    r = assess(_port(3389))
    assert r.level == Level.CRITICAL and r.base == Level.HIGH
    assert L.REMOTE_ACCESS_SERVICE in r.reasons and L.NEW_OPEN_PORT in r.reasons
    assert r.rule_id == "high-risk-port-added"


def test_porta_redis_e_data_service():
    r = assess(_port(6379))
    assert r.level == Level.CRITICAL and L.DATA_SERVICE in r.reasons


def test_porta_admin_parseada_da_key_sem_metadata():
    r = assess(_port(3389, meta={}))               # sem metadata -> parseia da key
    assert r.level == Level.CRITICAL


def test_porta_admin_so_eleva_em_added():
    r = assess(_port(3389, etype=EventType.REMOVED))
    assert r.level == r.base and L.REMOTE_ACCESS_SERVICE not in r.reasons


# ── contexto de ativo ────────────────────────────────────────────────────────
def test_internet_exposto_marca_reason():
    r = assess(_port(443, ctx={"exposure": "internet"}))
    assert L.INTERNET_EXPOSED_ASSET in r.reasons


def test_porta_proibida_pela_politica_vira_critical():
    r = assess(_port(23, ctx={"forbidden_ports": [23]}))
    assert r.level == Level.CRITICAL and L.FORBIDDEN_PORT in r.reasons
    assert r.rule_id == "forbidden-port-open"


def test_porta_fora_do_esperado_vira_high():
    r = assess(_port(8080, ctx={"expected_ports": [443]}))
    assert r.level >= Level.HIGH and L.UNEXPECTED_PORT in r.reasons
    assert r.rule_id == "unexpected-port-open"


def test_porta_esperada_nao_marca_unexpected():
    r = assess(_port(443, ctx={"expected_ports": [443, 80]}))
    assert L.UNEXPECTED_PORT not in r.reasons


def test_ativo_critico_anota_reason():
    r = assess(_port(3389, ctx={"criticality": "critical"}))
    assert L.CRITICAL_ASSET in r.reasons        # anotação; nível já era CRITICAL


# ── outros kinds ─────────────────────────────────────────────────────────────
def test_mailsec_dmarc_p_none_vira_high():
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, "x.com|DMARC",
              old_value="p=quarantine", new_value="v=DMARC1; p=none", metadata={"p": "none"})
    r = assess(e)
    assert r.level == Level.HIGH and L.DMARC_NOT_ENFORCED in r.reasons


def test_mailsec_dmarc_enforcado_nao_eleva():
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, "x.com|DMARC",
              old_value="p=none", new_value="v=DMARC1; p=reject", metadata={"p": "reject"})
    r = assess(e)
    assert L.DMARC_NOT_ENFORCED not in r.reasons and r.level == r.base


def test_takeover_critical_confidence():
    fp = Event("x.com", EventType.ADDED, Kind.TAKEOVER, "blog.x.com", new_value="GH",
               metadata={"service": "GitHub Pages", "reason": "fingerprint de recurso"})
    dang = Event("x.com", EventType.ADDED, Kind.TAKEOVER, "b.x.com", new_value="Azure",
                 metadata={"reason": "CNAME dangling (NXDOMAIN)"})
    rf, rd = assess(fp), assess(dang)
    assert rf.level == Level.CRITICAL and L.SUBDOMAIN_TAKEOVER in rf.reasons
    assert rf.confidence == Confidence.CONFIRMED     # fingerprint = observação direta
    assert rd.confidence == Confidence.HIGH          # dangling por NXDOMAIN = inferência


def test_severity_delega_para_assess():
    assert severity(_port(3389)) == Level.CRITICAL
    assert severity(_port(80)) == Level.HIGH


def test_reason_labels_traduz():
    r = assess(_port(3389))
    labels = r.reason_labels()
    assert any("acesso remoto" in x for x in labels)
