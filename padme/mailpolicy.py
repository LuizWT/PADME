"""Leitura da postura de e-mail (SPF/DMARC) a partir do TXT publicado.

Compartilhado pelo collector (metadata), pelo motor de risco (reason codes) e
pelo painel (problemas abertos) — uma única interpretação das políticas.
"""

from __future__ import annotations

# qualificador do mecanismo `all` do SPF (RFC 7208 §5.1): o que vale para
# quem NÃO casou nenhum mecanismo anterior. Sem prefixo = "+".
_PERMISSIVE_ALL = {"+", "?"}


def spf_all_qualifier(spf: str) -> str:
    """'+', '?', '~', '-' do termo `all`, ou '' se o registro não tem `all`."""
    for term in spf.lower().split()[1:]:
        if term in ("all", "+all", "?all", "~all", "-all"):
            return "+" if term == "all" else term[0]
    return ""


def dmarc_tag(dmarc: str, tag: str) -> str:
    """Valor de uma tag do DMARC (p, sp, pct...), em minúsculas; '' se ausente."""
    for part in dmarc.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() == tag:
            return v.strip().lower()
    return ""


def weaknesses(kind: str, txt: str) -> list[str]:
    """Fraquezas explícitas na política publicada (`kind` = 'spf' | 'dmarc').

    SPF `+all`/`all` autoriza qualquer servidor; `?all` é neutro (não protege).
    DMARC `p=none` não bloqueia nada; `sp=none` deixa os SUBDOMÍNIOS spoofáveis
    mesmo com `p` rígido (só reportado quando `p` protege, para não duplicar).
    Ausência de SPF/DMARC não entra aqui: domínio que não manda e-mail pode não
    publicar, e a REMOÇÃO já vira evento próprio."""
    txt = txt or ""
    out: list[str] = []
    if kind == "spf":
        q = spf_all_qualifier(txt)
        if q in _PERMISSIVE_ALL:
            out.append(f"SPF {'+all' if q == '+' else '?all'} (qualquer servidor passa)")
    elif kind == "dmarc":
        p = dmarc_tag(txt, "p")
        if p == "none":
            out.append("DMARC p=none (não bloqueia spoofing)")
        elif dmarc_tag(txt, "sp") == "none":
            out.append("DMARC sp=none (subdomínios spoofáveis)")
    return out
