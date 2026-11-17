"""Versões de serviço com CVE conhecida, consultadas no OSV (osv.dev).

O port-scan já lê a versão de alguns serviços: o banner do SSH e o handshake do
MySQL/MariaDB. Quando essa versão traz a revisão da distro (`OpenSSH_9.2p1
Debian-2+deb12u3`, `MariaDB 10.11.6-0+deb12u1`), dá para saber o pacote exato
instalado, e o OSV diz quais CVEs aquele pacote ainda tem.

Regras:

- **Só versão de pacote de distro.** Versão "pelada" (`nginx/1.22.1`, `OpenSSH_9.6`
  compilado à mão) não é consultada: a distro corrige sem mudar o número upstream,
  e o OSV indexa versões por ecossistema de pacote.
- **Só CVE com correção publicada** para aquela versão da distro. O que a distro
  marcou como sem correção (ou ainda não corrigiu) entra só na contagem
  `unfixed`, sem virar problema: atualizar não resolveria.
- **Um problema por porta**, com a lista de CVEs e a pior severidade.
- **Privacidade:** a consulta leva só ecossistema, pacote e versão. Nenhum host,
  IP ou banner sai da máquina.
- **Falha = inconclusivo.** Rede ou API fora do ar devolve `None`: quem chama
  preserva o estado anterior em vez de dizer que os CVEs sumiram.
- **Cache de 24h** por (ecossistema, pacote, versão), no SQLite.

O mapeamento produto -> pacote mora em `padme/data/osv_products.json`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any, Protocol

import httpx

from .risk import CVE_RANK as SEVERITY_RANK

log = logging.getLogger("padme")

API = "https://api.osv.dev/v1"
CACHE_TTL = 24 * 3600      # s: um par (pacote, versão) é consultado no máx. 1x por dia
_BATCH = 1000              # consultas por chamada do querybatch
_PAGES = 5                 # páginas extras por consulta (next_page_token)
_PARALLEL = 8              # GETs de /vulns/{id} ao mesmo tempo
_MAX_VULNS_KEPT = 50       # CVEs guardados no metadata de um record

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_LABELS = {"critical": "critical", "high": "high", "important": "high",
           "moderate": "medium", "medium": "medium", "low": "low", "negligible": "low"}


# ── produto do banner -> pacote da distro ──────────────────────────────────
@dataclass(frozen=True)
class Package:
    """Pacote de distro identificado a partir de um banner."""
    ecosystem: str          # ecossistema do OSV: "Debian:12", "Ubuntu:22.04:LTS"
    name: str               # pacote-fonte da distro: "openssh", "mariadb-10.6"
    version: str            # versão completa, com epoch: "1:9.2p1-2+deb12u3"
    product: str            # como o banner chama: "OpenSSH", "MariaDB", "MySQL"
    inferred: bool = False  # versão da distro deduzida pela versão upstream

    @property
    def confidence(self) -> str:
        return "medium" if self.inferred else "high"


_PRODUCTS: dict[str, Any] | None = None


def _products() -> dict[str, Any]:
    global _PRODUCTS
    if _PRODUCTS is None:
        raw = resources.files("padme").joinpath("data/osv_products.json").read_text("utf-8")
        _PRODUCTS = {k: v for k, v in json.loads(raw).items() if not k.startswith("_")}
    return _PRODUCTS


# SSH: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3" / "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
_SSH_DISTRO = re.compile(
    r"^SSH-[\d.]+-OpenSSH_(?P<up>\d[\w.]*)\s+(?P<distro>Debian|Ubuntu)-(?P<rev>[\w.+~]+)")
# MySQL/MariaDB (banner decodificado pelo ports.py): "MariaDB 10.11.6-0+deb12u1"
_DB_DISTRO = re.compile(r"^(?P<product>MariaDB|MySQL) (?P<up>\d+\.\d+\.\d+)-(?P<rev>[\w.+~]+)$")
_DEB_RELEASE = re.compile(r"\+deb(\d+)u\d+")
_UBUNTU_RELEASE = re.compile(r"ubuntu0\.(\d\d\.\d\d)(?:\.|$)")


def _parse_banner(banner: str) -> tuple[str, str, str, str] | None:
    """(produto, distro, upstream, revisão) de um banner com revisão de distro."""
    b = (banner or "").strip()
    m = _SSH_DISTRO.match(b)
    if m:
        return "openssh", m.group("distro").lower(), m.group("up"), m.group("rev")
    m = _DB_DISTRO.match(b)
    if m:
        rev = m.group("rev")
        distro = "debian" if "+deb" in rev else "ubuntu" if "ubuntu" in rev else ""
        if distro:
            return m.group("product").lower(), distro, m.group("up"), rev
    return None


def package_of(metadata: dict[str, Any] | None) -> Package | None:
    """Pacote de distro de uma porta aberta (metadata do Record de porta), ou
    None quando o banner não diz o bastante para uma consulta exata."""
    md = metadata or {}
    parsed = _parse_banner(str(md.get("banner") or ""))
    if parsed is None:
        return None
    product, distro, upstream, rev = parsed
    if "~bpo" in rev:   # backport: versão fora da série da distro, sem como mapear
        return None
    spec = (_products().get(product) or {}).get(distro)
    if not spec:
        return None
    by_release = spec.get("package")
    upstream_of = spec.get("upstream") or {}
    releases = set(by_release) if isinstance(by_release, dict) else set(upstream_of)

    release_re = _DEB_RELEASE if distro == "debian" else _UBUNTU_RELEASE
    m = release_re.search(rev)
    inferred = m is None
    if m:
        release = m.group(1)
    else:  # sem a versão da distro no banner: só se a upstream for de uma versão só
        matches = [rel for rel, up in upstream_of.items() if up == upstream]
        if len(matches) != 1:
            return None
        release = matches[0]
    if release not in releases:
        return None
    name = by_release.get(release) if isinstance(by_release, dict) else by_release
    if not name:
        return None
    epoch = str(spec.get("epoch") or "")
    version = f"{epoch + ':' if epoch else ''}{upstream}-{rev}"
    ecosystem = f"Debian:{release}" if distro == "debian" else f"Ubuntu:{release}:LTS"
    label = {"openssh": "OpenSSH", "mariadb": "MariaDB", "mysql": "MySQL"}[product]
    return Package(ecosystem, str(name), version, label, inferred)


# ── severidade ─────────────────────────────────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """Arredondamento para cima com uma casa, como na especificação do CVSS 3.1
    (inteiro intermediário evita erro de ponto flutuante)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Nota base de um vetor CVSS 3.0/3.1 (`CVSS:3.1/AV:N/AC:L/...`), ou None se
    o vetor não for v3 ou estiver incompleto."""
    parts = (vector or "").strip().split("/")
    if not parts[0].startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
    try:
        if m["S"] not in ("U", "C"):
            return None
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10.0))


def label_of(score: float) -> str:
    """Faixa qualitativa do CVSS: 9+ critical, 7+ high, 4+ medium, resto low."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def record_severity(rec: dict[str, Any]) -> tuple[str, float | None]:
    """(severidade, nota) de um registro do OSV. Usa a nota do vetor CVSS v3;
    sem ele (CVSS v4, só rótulo da distro), a classificação que o registro já
    traz. ('', None) quando não há nenhuma das duas."""
    score: float | None = None
    label = ""
    for s in rec.get("severity") or []:
        if not isinstance(s, dict):
            continue
        typ, val = str(s.get("type", "")).upper(), str(s.get("score", ""))
        if typ == "CVSS_V3":
            sc = cvss3_score(val)
            if sc is not None and (score is None or sc > score):
                score = sc
        elif not label:
            label = _LABELS.get(val.strip().lower(), "")   # ex.: {"type": "Ubuntu", "score": "high"}
    if score is not None:
        return label_of(score), score
    sources: list[Any] = [rec.get("database_specific")]
    for aff in rec.get("affected") or []:
        if isinstance(aff, dict):
            sources += [aff.get("database_specific"), aff.get("ecosystem_specific")]
    for src in sources:
        if isinstance(src, dict):
            found = _LABELS.get(str(src.get("severity", "")).strip().lower(), "")
            if found:
                return found, None
    return label, None


# ── versões Debian/Ubuntu (ordem do dpkg) ─────────────────────────────────
def _order(c: str) -> int:
    if c.isdigit() or not c:
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """Comparação de upstream ou revisão como o dpkg: blocos de não-dígito
    (com `~` antes de tudo, letras antes de símbolos) e de número."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        ni = i
        while ni < len(a) and a[ni].isdigit():
            ni += 1
        nj = j
        while nj < len(b) and b[nj].isdigit():
            nj += 1
        da, db = int(a[i:ni] or 0), int(b[j:nj] or 0)
        if da != db:
            return 1 if da > db else -1
        i, j = ni, nj
    return 0


def _split_version(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)   # epoch: antes do 1º ':'
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    try:
        ep = int(epoch or 0)
    except ValueError:
        ep = 0
    return ep, upstream, revision


def debian_version_cmp(a: str, b: str) -> int:
    """<0, 0 ou >0, como `dpkg --compare-versions` (epoch, upstream, revisão)."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def fixed_in(vulns: list[dict[str, Any]]) -> str | None:
    """Menor versão que corrige TODOS os CVEs da lista (a maior das correções)."""
    best: str | None = None
    for v in vulns:
        f = v.get("fixed")
        if f and (best is None or debian_version_cmp(str(f), best) > 0):
            best = str(f)
    return best


# ── interpretação dos registros ────────────────────────────────────────────
def cve_ids(rec: dict[str, Any]) -> list[str]:
    """CVEs de que um registro trata. Registro da distro por CVE (DEBIAN-CVE-…,
    UBUNTU-CVE-…) aponta o CVE no id/upstream; aviso de segurança (DSA, DLA,
    USN) lista os CVEs que corrige. Sem nenhum CVE, vale o próprio id."""
    rid = str(rec.get("id") or "")
    ids: list[Any] = [rid, *(rec.get("aliases") or []), *(rec.get("upstream") or [])]
    if not _CVE_RE.search(rid):   # aviso (DSA/USN): os relacionados são os que ele corrige
        ids += rec.get("related") or []
    found = sorted({m.group(0) for i in ids if isinstance(i, str)
                    for m in [_CVE_RE.fullmatch(i) or _CVE_RE.search(i)] if m})
    return found or ([rid] if rid else [])


def fixed_version(rec: dict[str, Any], pkg: Package) -> str | None:
    """Versão que corrige o registro para ESTE pacote e ecossistema, ou None
    quando a distro não publicou correção."""
    for aff in rec.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        p = aff.get("package") or {}
        if p.get("name") != pkg.name or p.get("ecosystem") != pkg.ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for ev in (rng or {}).get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    return str(ev["fixed"])
    return None


def assess_package(pkg: Package, records: list[dict[str, Any]]) -> dict[str, Any]:
    """Junta os registros do OSV de um pacote por CVE (um CVE pode vir do
    registro da distro e de um aviso de segurança ao mesmo tempo). Devolve
    {"vulns": [com correção, pior primeiro], "unfixed": n}."""
    entries: dict[str, dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict) or rec.get("withdrawn"):
            continue
        fixed = fixed_version(rec, pkg)
        sev, score = record_severity(rec)
        for cid in cve_ids(rec):
            e = entries.setdefault(cid, {"id": cid, "severity": "", "score": None,
                                         "fixed": None, "sources": []})
            e["fixed"] = e["fixed"] or fixed
            if score is not None and (e["score"] is None or score > e["score"]):
                e["score"], e["severity"] = score, sev
            elif e["score"] is None and SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(
                    e["severity"], 0):
                e["severity"] = sev
            if rec.get("id") and rec["id"] not in e["sources"]:
                e["sources"].append(str(rec["id"]))
    fixed_list = [e for e in entries.values() if e["fixed"]]
    fixed_list.sort(key=lambda e: (-SEVERITY_RANK.get(e["severity"] or "unknown", 0),
                                   -(e["score"] or 0.0), e["id"]))
    return {"vulns": fixed_list, "unfixed": len(entries) - len(fixed_list)}


# ── consulta ───────────────────────────────────────────────────────────────
class Cache(Protocol):
    def osv_cache_get(self, ecosystem: str, package: str, version: str,
                      max_age: float) -> dict[str, Any] | None: ...

    def osv_cache_put(self, ecosystem: str, package: str, version: str,
                      result: dict[str, Any]) -> None: ...


def _query(pkg: Package, page_token: str = "") -> dict[str, Any]:
    """Uma consulta do querybatch: só ecossistema, pacote e versão (privacidade)."""
    q: dict[str, Any] = {"package": {"ecosystem": pkg.ecosystem, "name": pkg.name},
                         "version": pkg.version}
    if page_token:
        q["page_token"] = page_token
    return q


async def _batch_ids(client: httpx.AsyncClient, packages: list[Package],
                     api: str) -> dict[Package, list[str]]:
    """Ids de vulnerabilidade por pacote via /v1/querybatch (paginado).
    Exceção de rede/HTTP propaga: a consulta inteira fica inconclusiva."""
    out: dict[Package, list[str]] = {p: [] for p in packages}
    pending: list[tuple[Package, str]] = [(p, "") for p in packages]
    for _ in range(_PAGES + 1):
        if not pending:
            break
        nxt: list[tuple[Package, str]] = []
        for start in range(0, len(pending), _BATCH):
            chunk = pending[start:start + _BATCH]
            resp = await client.post(f"{api}/querybatch",
                                     json={"queries": [_query(p, t) for p, t in chunk]})
            resp.raise_for_status()
            results = (resp.json() or {}).get("results") or []
            if len(results) != len(chunk):
                raise ValueError("querybatch: número de resultados não bate com o de consultas")
            for (pkg, _tok), res in zip(chunk, results):
                for v in (res or {}).get("vulns") or []:
                    vid = (v or {}).get("id")
                    if vid and vid not in out[pkg]:
                        out[pkg].append(str(vid))
                token = (res or {}).get("next_page_token")
                if token:
                    nxt.append((pkg, str(token)))
        pending = nxt
    if pending:
        raise ValueError("querybatch: paginação maior que o teto")
    return out


async def lookup(packages: set[Package], cache: Cache, client: httpx.AsyncClient,
                 api: str = API) -> dict[Package, dict[str, Any] | None]:
    """Avaliação de cada pacote ({"vulns": [...], "unfixed": n}). None = não deu
    para saber (rede, API, registro faltando): quem chama preserva o estado."""
    result: dict[Package, dict[str, Any] | None] = {}
    missing: list[Package] = []
    for pkg in sorted(packages, key=lambda p: (p.ecosystem, p.name, p.version)):
        cached = cache.osv_cache_get(pkg.ecosystem, pkg.name, pkg.version, CACHE_TTL)
        if cached is not None:
            result[pkg] = cached
        else:
            missing.append(pkg)
    if not missing:
        return result

    try:
        ids_by_pkg = await _batch_ids(client, missing, api)
    except Exception as exc:  # noqa: BLE001 — falha da consulta = inconclusivo
        log.warning("OSV: consulta falhou (%s); CVEs anteriores preservados",
                    type(exc).__name__)
        return {**result, **{p: None for p in missing}}

    sem = asyncio.Semaphore(_PARALLEL)
    memo: dict[str, dict[str, Any] | None] = {}

    async def fetch(vid: str) -> dict[str, Any] | None:
        if vid in memo:
            return memo[vid]
        async with sem:
            if vid in memo:
                return memo[vid]
            try:
                resp = await client.get(f"{api}/vulns/{vid}")
                if resp.status_code == 404:
                    memo[vid] = {}           # existe na busca, não no detalhe: ignora
                else:
                    resp.raise_for_status()
                    data = resp.json()
                    memo[vid] = data if isinstance(data, dict) else None
            except Exception as exc:  # noqa: BLE001
                log.debug("OSV: %s falhou (%s)", vid, type(exc).__name__)
                memo[vid] = None
            return memo[vid]

    all_ids = sorted({i for ids in ids_by_pkg.values() for i in ids})
    await asyncio.gather(*(fetch(i) for i in all_ids))

    for pkg in missing:
        recs = [memo.get(i) for i in ids_by_pkg[pkg]]
        if any(r is None for r in recs):
            result[pkg] = None
            continue
        assessment = assess_package(pkg, [r for r in recs if r])
        # registro da distro sem nota: usa a do registro do próprio CVE
        for e in assessment["vulns"]:
            if not e["severity"] and _CVE_RE.fullmatch(e["id"]):
                rec = await fetch(e["id"])
                if rec:
                    e["severity"], e["score"] = record_severity(rec)
            e["severity"] = e["severity"] or "unknown"
        assessment["vulns"].sort(key=lambda e: (-SEVERITY_RANK.get(e["severity"], 0),
                                                -(e["score"] or 0.0), e["id"]))
        cache.osv_cache_put(pkg.ecosystem, pkg.name, pkg.version, assessment)
        result[pkg] = assessment
    return result


def summary(pkg_name: str, version: str, vulns: list[dict[str, Any]]) -> str:
    """Resumo humano do record: pacote, versão, o pior CVE e a versão que
    corrige todos."""
    worst = vulns[0]
    score = f" {worst['score']:.1f}" if worst.get("score") is not None else ""
    head = f"{pkg_name} {version} · "
    if len(vulns) == 1:
        text = f"{head}{worst['id']} ({worst['severity']}{score})"
    else:
        text = f"{head}{len(vulns)} CVEs, o pior {worst['id']} ({worst['severity']}{score})"
    fix = fixed_in(vulns)
    return f"{text} · corrige em {fix}" if fix else text


def record_metadata(port: Any, pkg: Package, assessment: dict[str, Any]) -> dict[str, Any]:
    vulns = assessment["vulns"]
    worst = vulns[0]
    return {
        "port": port, "product": pkg.product, "package": pkg.name,
        "ecosystem": pkg.ecosystem, "version": pkg.version,
        "cves": [v["id"] for v in vulns], "max_severity": worst["severity"],
        "max_score": worst.get("score"), "fixed_in": fixed_in(vulns),
        "unfixed": int(assessment.get("unfixed") or 0),
        "vulns": [{k: v.get(k) for k in ("id", "severity", "score", "fixed")}
                  for v in vulns[:_MAX_VULNS_KEPT]],
        "confidence": pkg.confidence, "source": "osv.dev",
    }
