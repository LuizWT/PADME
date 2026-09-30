"""Postura de e-mail (SPF/DMARC): interpretação ÚNICA para collector, motor de
risco e painel.

SPF EFETIVO (RFC 7208): o TXT do apex sozinho não diz tudo — `include:` e
`redirect=` delegam a decisão a outros domínios. `spf_effective` percorre a
cadeia como um receptor faria para um IP QUALQUER (o de um atacante): o que
casa esse IP decide o resultado. Casam "qualquer IP" o `all`, um `include:` de
domínio cujo SPF passa qualquer um, e faixas `ip4`/`ip6` enormes. A consulta DNS
é injetada (`fetch`), então a avaliação é pura e testável.

DMARC (RFC 7489): `p=none` não bloqueia; `sp=none` expõe subdomínios; `pct<100`
e `t=y` fazem parte das mensagens cair UM nível de política (§6.6.4): com
`p=quarantine` essa parte passa sem política nenhuma.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Awaitable, Callable

# ── reason codes (estáveis p/ webhook/n8n; o risk.py reexporta) ───────────────
SPF_PERMISSIVE = "SPF_PERMISSIVE"
SPF_PERMERROR = "SPF_PERMERROR"
DMARC_NOT_ENFORCED = "DMARC_NOT_ENFORCED"
DMARC_SUBDOMAINS_NOT_ENFORCED = "DMARC_SUBDOMAINS_NOT_ENFORCED"
DMARC_PARTIAL = "DMARC_PARTIAL"

SPF_EFFECTIVE_SUFFIX = "|SPF-EFFECTIVE"   # key do registro de postura efetiva

_MAX_LOOKUPS = 10          # RFC 7208 §4.6.4: termos que consultam DNS
_BROAD_PREFIX = {"ip4": 8, "ip6": 16}   # /8 (16M IPs) ou maior = cabe atacante
_QUALIFIERS = "+-~?"
_LABEL = {"+": "+all", "-": "-all", "~": "~all", "?": "?all"}


@dataclass(frozen=True)
class MailFinding:
    code: str
    label: str
    rule: str
    high: bool   # True: eleva a HIGH; False: só anota (explica, não escala)


# ── parsing básico ────────────────────────────────────────────────────────────
def is_spf(txt: str) -> bool:
    t = txt.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def spf_all_qualifier(spf: str) -> str:
    """'+', '?', '~', '-' do termo `all` literal, ou '' se não há `all`."""
    for term in spf.lower().split()[1:]:
        if term in ("all", "+all", "?all", "~all", "-all"):
            return "+" if term == "all" else term[0]
    return ""


def dmarc_tag(dmarc: str, tag: str) -> str:
    """Valor de uma tag do DMARC (p, sp, pct, t...), minúsculo; '' se ausente."""
    for part in dmarc.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() == tag:
            return v.strip().lower()
    return ""


# ── SPF efetivo ───────────────────────────────────────────────────────────────
class SpfInconclusive(Exception):
    """Consulta DNS sem resposta definitiva (timeout/SERVFAIL): quem chama
    preserva o estado anterior em vez de concluir qualquer coisa."""


@dataclass(frozen=True)
class SpfVerdict:
    result: str        # '+', '-', '~', '?' ou 'permerror'
    via: str           # o que decidiu (all, include:x, ip4:.../n, redirect:y, padrão)
    lookups: int = 0

    @property
    def value(self) -> str:
        """Resumo estável (vira o `value` do registro): só muda se a postura mudar."""
        if self.result == "permerror":
            return f"permerror · {self.via}"
        return f"{_LABEL[self.result]} · {self.via}"


# fetch(domínio) -> lista de TXT "v=spf1" do domínio ([] = sem SPF);
# levanta SpfInconclusive em erro transitório.
Fetch = Callable[[str], Awaitable[list[str]]]


class _PermError(Exception):
    pass


def _split(term: str) -> tuple[str, str, str]:
    """termo -> (qualificador, mecanismo, argumento)."""
    q = term[0] if term[0] in _QUALIFIERS else "+"
    body = term[1:] if term[0] in _QUALIFIERS else term
    name, sep, arg = body.partition(":")
    if not sep and "/" in name:          # a/24, mx/24 (cidr sem domínio)
        name, _, arg = name.partition("/")
        arg = "/" + arg
    return q, name, arg


def _broad(name: str, arg: str) -> str | None:
    """'ip4:x/n' se a faixa é tão grande que um atacante cabe nela."""
    try:
        net = ipaddress.ip_network(arg, strict=False)
    except ValueError as exc:
        raise _PermError(f"{name}:{arg} inválido") from exc
    if net.prefixlen <= _BROAD_PREFIX[name]:
        return f"{name}:{arg} ({net.num_addresses:,} endereços)".replace(",", ".")
    return None


async def spf_effective(record: str, fetch: Fetch) -> SpfVerdict:
    """Resultado do SPF para um IP arbitrário, seguindo include/redirect.
    Levanta SpfInconclusive se alguma consulta necessária não respondeu."""
    state = {"lookups": 0}
    cache: dict[str, list[str]] = {}

    async def spf_of(domain: str) -> str:
        state["lookups"] += 1
        if state["lookups"] > _MAX_LOOKUPS:
            raise _PermError(f"mais de {_MAX_LOOKUPS} consultas DNS (RFC 7208 §4.6.4)")
        if "%" in domain:   # macro: depende do remetente, não dá p/ avaliar estático
            return ""
        if domain not in cache:
            cache[domain] = await fetch(domain)
        recs = cache[domain]
        if not recs:
            raise _PermError(f"{domain} sem registro SPF")
        if len(recs) > 1:
            raise _PermError(f"{domain} com {len(recs)} registros SPF")
        return recs[0]

    async def check(text: str) -> tuple[str, str]:
        redirect = None
        for term in text.split()[1:]:
            t = term.lower()
            if "=" in t.split(":", 1)[0]:          # modificador (redirect=, exp=, …)
                name, _, val = t.partition("=")
                if name == "redirect":
                    redirect = val
                continue
            q, name, arg = _split(t)
            if name == "all":
                return q, "all"
            if name in ("ip4", "ip6"):
                wide = _broad(name, arg)
                if wide:
                    return q, wide
            elif name in ("a", "mx", "ptr", "exists"):
                state["lookups"] += 1   # consulta, mas não casa um IP arbitrário
                if state["lookups"] > _MAX_LOOKUPS:
                    raise _PermError(f"mais de {_MAX_LOOKUPS} consultas DNS (RFC 7208 §4.6.4)")
            elif name == "include":
                sub = await spf_of(arg)
                if sub:
                    r, via = await check(sub)
                    if r == "+":   # o incluído passa qualquer um -> include casa
                        return q, f"include:{arg} → {via}"
            else:
                raise _PermError(f"mecanismo desconhecido: {term}")
        if redirect:   # só vale se nada casou (e não há `all`)
            sub = await spf_of(redirect)
            if sub:
                r, via = await check(sub)
                return r, f"redirect:{redirect} → {via}"
        return "?", "sem all (padrão neutro)"

    try:
        result, via = await check(record)
    except _PermError as exc:
        return SpfVerdict("permerror", str(exc), state["lookups"])
    return SpfVerdict(result, via, state["lookups"])


# ── achados (risco + painel) ──────────────────────────────────────────────────
def _spf_effective_findings(value: str, md: dict) -> list[MailFinding]:
    result = md.get("result")
    if not result:   # sem metadata (ex.: evento antigo): lê do resumo "+all · via"
        head = value.split(" ", 1)[0]
        result = "permerror" if head == "permerror" else head[:1]
    via = md.get("via") or (value.split(" · ", 1)[1] if " · " in value else "")
    if result == "permerror":
        return [MailFinding(SPF_PERMERROR, f"SPF quebrado (permerror: {via})",
                            "spf-permerror", True)]
    if result in ("+", "?"):
        what = "qualquer servidor passa" if result == "+" else "resultado neutro, não protege"
        return [MailFinding(SPF_PERMISSIVE, f"SPF efetivo {_LABEL[result]} via {via} ({what})",
                            "spf-permissive", True)]
    return []


def _dmarc_findings(txt: str, md: dict) -> list[MailFinding]:
    if (md.get("records") or 1) > 1:
        return [MailFinding(DMARC_NOT_ENFORCED,
                            "múltiplos registros DMARC (receptores ignoram a política)",
                            "dmarc-multiple", True)]
    p, sp = dmarc_tag(txt, "p"), dmarc_tag(txt, "sp")
    if p not in ("quarantine", "reject"):
        label = "DMARC p=none (não bloqueia spoofing)" if p == "none" \
            else "DMARC sem p= válido (tratado como none)"
        return [MailFinding(DMARC_NOT_ENFORCED, label, "dmarc-p-none", True)]
    out: list[MailFinding] = []
    if sp == "none":
        out.append(MailFinding(DMARC_SUBDOMAINS_NOT_ENFORCED,
                               "DMARC sp=none (subdomínios spoofáveis)", "dmarc-sp-none", True))
    # pct<100 / t=y: a parte não selecionada cai UM nível (RFC 7489 §6.6.4)
    lower = "nenhuma política" if p == "quarantine" else "quarentena em vez de rejeição"
    pct_raw = dmarc_tag(txt, "pct")
    pct = int(pct_raw) if pct_raw.isdigit() else 100
    if pct < 100:
        out.append(MailFinding(DMARC_PARTIAL,
                               f"DMARC pct={pct}: {100 - pct}% das mensagens falsas "
                               f"recebem {lower}", "dmarc-partial", p == "quarantine"))
    if dmarc_tag(txt, "t") == "y":
        out.append(MailFinding(DMARC_PARTIAL,
                               f"DMARC em modo de teste (t=y): mensagens falsas recebem {lower}",
                               "dmarc-testing", p == "quarantine"))
    return out


def findings(key: str, value: str, md: dict | None = None) -> list[MailFinding]:
    """Fraquezas explícitas de um registro MAILSEC (`key` = 'apex|TIPO').

    O TXT bruto do SPF (`|SPF`) não é julgado aqui: quem julga é o registro de
    postura efetiva (`|SPF-EFFECTIVE`), que enxerga include/redirect. Ausência
    de SPF/DMARC não é achado (domínio sem e-mail pode não publicar); a
    REMOÇÃO já é evento próprio."""
    md = md or {}
    value = value or ""
    if key.endswith(SPF_EFFECTIVE_SUFFIX):
        return _spf_effective_findings(value, md)
    if key.endswith("|DMARC"):
        return _dmarc_findings(value, md)
    return []
