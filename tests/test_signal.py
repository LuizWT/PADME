"""Teste da qualidade de sinal: subdomínio live/quiet."""

from padme.engine import annotate_liveness
from padme.models import Kind, Record


def test_liveness():
    recs = [
        Record(Kind.SUBDOMAIN, "www.x.com"),      # tem http+porta -> live
        Record(Kind.SUBDOMAIN, "api.x.com"),      # só tls -> live
        Record(Kind.SUBDOMAIN, "dead.x.com"),     # nada -> quiet
        Record(Kind.HTTP, "http://www.x.com", "200 | nginx"),
        Record(Kind.PORT, "www.x.com:443", "open"),
        Record(Kind.TLS, "api.x.com:443", "issuer=LE"),
    ]
    out = annotate_liveness(recs)
    sub = {r.key: r.value for r in out if r.kind == Kind.SUBDOMAIN}
    assert sub == {"www.x.com": "live", "api.x.com": "live", "dead.x.com": "quiet"}
    # registros não-subdomínio ficam intactos
    assert sum(1 for r in out if r.kind != Kind.SUBDOMAIN) == 3


def test_liveness_sem_subdominio():
    recs = [Record(Kind.PORT, "x.com:22", "open")]
    assert annotate_liveness(recs) == recs
