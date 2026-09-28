"""Priorização contextual de risco (levels.assess).

Determinística e explicável: cada elevação tem um motivo nomeado, e sem contexto
aplicável a severidade é a base (compatível com o comportamento anterior).
"""

from padme.levels import Level, assess, severity
from padme.models import Event, EventType, Kind


def _port(port, etype=EventType.ADDED, meta=None):
    return Event("x.com", etype, Kind.PORT, f"x.com:{port}",
                 new_value="open", metadata=meta or {"port": port})


def test_porta_comum_nova_fica_na_base():
    r = assess(_port(443))
    assert r.level == Level.HIGH and r.base == Level.HIGH
    assert r.reasons == []                       # sem elevação


def test_porta_rdp_nova_vira_critical_com_motivo():
    r = assess(_port(3389))
    assert r.level == Level.CRITICAL and r.base == Level.HIGH
    assert any("RDP" in m and "3389" in m for m in r.reasons)


def test_porta_redis_nova_vira_critical():
    r = assess(_port(6379))
    assert r.level == Level.CRITICAL and any("Redis" in m for m in r.reasons)


def test_porta_admin_parseada_da_key_sem_metadata():
    r = assess(_port(3389, meta={}))             # sem metadata -> parseia da key
    assert r.level == Level.CRITICAL


def test_porta_admin_so_eleva_em_added_nao_removed():
    r = assess(_port(3389, etype=EventType.REMOVED))
    assert r.level == r.base and r.reasons == []  # porta fechando não é exposição


def test_mailsec_dmarc_p_none_vira_high():
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, "x.com|DMARC",
              old_value="p=quarantine", new_value="v=DMARC1; p=none", metadata={"p": "none"})
    r = assess(e)
    assert r.level == Level.HIGH and any("p=none" in m for m in r.reasons)


def test_mailsec_dmarc_enforcado_nao_eleva():
    e = Event("x.com", EventType.CHANGED, Kind.MAILSEC, "x.com|DMARC",
              old_value="p=none", new_value="v=DMARC1; p=reject", metadata={"p": "reject"})
    r = assess(e)
    assert r.reasons == [] and r.level == r.base


def test_takeover_critical_com_motivo():
    e = Event("x.com", EventType.ADDED, Kind.TAKEOVER, "blog.x.com",
              new_value="GitHub Pages | ...", metadata={"service": "GitHub Pages"})
    r = assess(e)
    assert r.level == Level.CRITICAL and any("takeover" in m for m in r.reasons)


def test_httpsec_changed_medium_favicon_changed_low():
    hs = Event("x.com", EventType.CHANGED, Kind.HTTPSEC, "https://x.com", "a", "b")
    fv = Event("x.com", EventType.CHANGED, Kind.FAVICON, "x.com", "aaa", "bbb")
    assert severity(hs) == Level.MEDIUM
    assert severity(fv) == Level.LOW


def test_severity_delega_para_assess():
    assert severity(_port(3389)) == Level.CRITICAL   # mesma régua no filtro por canal
    assert severity(_port(80)) == Level.HIGH
