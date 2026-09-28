"""Fingerprint HTTP leve: um GET por host (http e https).

Registra status, header Server e o <title> da página. Mudança de status
(ex: 404 -> 200) ou de servidor costuma indicar um serviço novo ou alterado.

Segurança (anti-SSRF): NÃO segue redirects por padrão — um `Location:
http://127.0.0.1/` transformaria o monitor em proxy pra rede interna. Quando
não segue, registra o destino do redirect.

Memória: lê no máximo `max_bytes` do corpo (streaming) — não baixa uma página
de 100 MB só pra extrair um `<title>`. O corpo (truncado) é reaproveitado pelo
collector de takeover.

Confiabilidade: se nenhum dos esquemes respondeu (timeout/erro de conexão), o
resultado é `ok=False` — o estado HTTP anterior do host é preservado em vez de
virar "removido".
"""

from __future__ import annotations

import re

import httpx

from ..models import CollectionResult, Kind, Record

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
DEFAULT_MAX_BYTES = 262144  # 256 KiB — suficiente p/ <title> e fingerprints

# ── postura de cabeçalhos de segurança (sinal RED, sem request extra) ────────
# Reaproveita a MESMA resposta do GET. `value` lista o que FALTA (o achado);
# metadata guarda presença/ausência estruturada. HSTS só é avaliado em https
# (em http o browser ignora, seria falso positivo).
_SEC_HEADERS: list[tuple[str, str]] = [
    ("hsts", "strict-transport-security"),
    ("csp", "content-security-policy"),
    ("xfo", "x-frame-options"),
    ("nosniff", "x-content-type-options"),
    ("refpol", "referrer-policy"),
    ("permpol", "permissions-policy"),
]

# ── fingerprint de tecnologia (barato: só cabeçalhos já coletados) ───────────
# Rótulo derivado de Server / X-Powered-By / Via e de headers-assinatura. NÃO
# baixa conteúdo extra e NÃO é um evento próprio (a troca de stack já aparece
# como mudança do Server no value do HTTP). Serve de pivot no export/painel.
_TECH_TOKENS: list[tuple[str, tuple[str, ...]]] = [
    ("Cloudflare", ("cloudflare",)), ("AmazonS3", ("amazons3",)),
    ("nginx", ("nginx",)), ("Apache", ("apache",)), ("OpenResty", ("openresty",)),
    ("LiteSpeed", ("litespeed",)), ("IIS", ("microsoft-iis", "iis")),
    ("Caddy", ("caddy",)), ("Envoy", ("envoy",)), ("Varnish", ("varnish",)),
    ("gunicorn", ("gunicorn",)), ("Express", ("express",)), ("PHP", ("php",)),
    ("Tomcat", ("tomcat", "coyote")), ("Jetty", ("jetty",)),
    ("WordPress", ("wordpress", "wp-")), ("Vercel", ("vercel",)),
]
# headers cuja mera presença denuncia o serviço (nome do header -> rótulo)
_TECH_HEADER_HINTS: list[tuple[str, str]] = [
    ("cf-ray", "Cloudflare"), ("x-amz-cf-id", "CloudFront"),
    ("x-served-by", "Fastly"), ("x-vercel-id", "Vercel"),
    ("x-github-request-id", "GitHub"),
]


def _title(html: str) -> str:
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


def _security_posture(headers, scheme: str) -> tuple[list[str], list[str]]:
    """(presentes, ausentes) dos cabeçalhos de postura. Header presente mas
    vazio conta como AUSENTE. HSTS só entra em https."""
    present, missing = [], []
    for short, name in _SEC_HEADERS:
        if short == "hsts" and scheme != "https":
            continue
        v = (headers.get(name) or "").strip()
        (present if v else missing).append(short)
    return present, missing


def _tech_fingerprint(headers) -> list[str]:
    """Rótulos de tecnologia inferidos de cabeçalhos (determinístico, sem I/O)."""
    hay = " ".join((headers.get(h) or "").lower() for h in (
        "server", "x-powered-by", "via", "x-generator", "x-aspnet-version"))
    tech: list[str] = []
    for label, needles in _TECH_TOKENS:
        if any(n in hay for n in needles) and label not in tech:
            tech.append(label)
    for header, label in _TECH_HEADER_HINTS:
        if header in headers and label not in tech:
            tech.append(label)
    return tech


async def _fetch_limited(
    client: httpx.AsyncClient, url: str, follow_redirects: bool, max_bytes: int
) -> tuple[httpx.Response, str]:
    """GET com corpo limitado a `max_bytes`. Não lê corpo de redirect (3xx)."""
    async with client.stream("GET", url, follow_redirects=follow_redirects) as r:
        if 300 <= r.status_code < 400:
            return r, ""  # redirect: interessa o Location, não o corpo
        total = 0
        chunks: list[bytes] = []
        async for chunk in r.aiter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        return r, b"".join(chunks)[:max_bytes].decode("utf-8", errors="ignore")


async def collect_host(
    host: str,
    client: httpx.AsyncClient,
    cache: dict[str, str] | None = None,
    follow_redirects: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    security: bool = True,
) -> CollectionResult:
    records: list[Record] = []
    observed_any = False
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r, body = await _fetch_limited(client, url, follow_redirects, max_bytes)
        except Exception:
            continue  # esse esquema não respondeu; tenta o outro
        observed_any = True
        if cache is not None:  # reaproveitado pelo collector de takeover
            cache[url] = body
        server = r.headers.get("server", "")
        location = r.headers.get("location", "") if 300 <= r.status_code < 400 else ""
        title = ""
        detail = ""
        if location:
            detail = f"→ {location}"  # não seguimos: registramos o destino
        elif "text/html" in r.headers.get("content-type", ""):
            title = _title(body)
            detail = title
        tech = _tech_fingerprint(r.headers)
        value = f"{r.status_code} | {server} | {detail}".strip()
        records.append(Record(kind=Kind.HTTP, key=url, value=value, metadata={
            "status": r.status_code, "server": server, "title": title,
            "location": location or None, "scheme": scheme,
            "tech": tech or None,
        }))
        # postura de segurança: só em resposta que serve conteúdo (não em 3xx,
        # cujo endpoint real não é buscado). Mesma resposta -> sem request extra.
        if security and not location:
            present, missing = _security_posture(r.headers, scheme)
            posture = "faltando: " + ", ".join(missing) if missing else "completo"
            records.append(Record(kind=Kind.HTTPSEC, key=url, value=posture, metadata={
                "present": present, "missing": missing, "scheme": scheme,
            }))
    return CollectionResult(records=records, ok=observed_any)
