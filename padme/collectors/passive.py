"""Fontes passivas de subdomínio além do CT (crt.sh/crt.name).

Os logs de certificado não veem nome que nunca teve certificado próprio (atrás
de um wildcard, interno, só HTTP). Estas fontes públicas complementam:

  sem chave : certspotter (outro agregador de CT — cobre quando o crt.sh cai),
              otx (DNS passivo da AlienVault), wayback (URLs arquivadas),
              hackertarget (cota diária pequena: fica fora do padrão)
  com chave : securitytrails, virustotal (e otx aceita chave para mais cota)

Regras que mantêm o sinal limpo:
  - nome só vira subdomínio se RESOLVE agora (A/AAAA) e não só para o curinga
    de DNS — fonte histórica traz muito nome morto, e "existe um nome" sem
    prova é ruído;
  - é SUPLEMENTAR como o bruteforce: não decide o escopo de subdomínio, e
    nada sai do estado por ausência aqui (só com prova de DNS, no engine);
  - consultadas no máximo a cada `passive_every_hours` por alvo (mudam
    devagar; consultar a cada ciclo gasta cota e pode bloquear a chave);
  - cliente HTTP PRÓPRIO, com verificação de TLS (o dos alvos roda com
    verify=False) — leva chave de API, então não pode aceitar MITM;
  - corpo lido com teto de bytes e candidatos com teto de quantidade.

Ninguém aqui toca o alvo além da resolução DNS dos candidatos (com o mesmo
rate-limit do resto). Use somente em alvos autorizados.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Callable

import httpx

from ..models import CollectionResult, Kind, Record
from .bruteforce import resolve_hosts
from .subdomains import _extract_hosts

log = logging.getLogger("padme")

_MAX_BYTES = 5 * 1024 * 1024     # wayback de domínio grande passa fácil de MBs
_VT_MAX_PAGES = 5
_VT_BASE = "https://www.virustotal.com/api/v3/"
_USER_AGENT = "padme-asm (attack surface monitor; passive lookup)"


@dataclass(frozen=True)
class Source:
    url: Callable[[str], str]
    key_header: str = ""        # header da chave (vazio = fonte sem chave)
    key_required: bool = False
    text: bool = False          # corpo em texto (senão JSON)


SOURCES: dict[str, Source] = {
    "certspotter": Source(lambda a: "https://api.certspotter.com/v1/issuances"
                                    f"?domain={a}&include_subdomains=true&expand=dns_names"),
    "otx": Source(lambda a: f"https://otx.alienvault.com/api/v1/indicators/domain/{a}/passive_dns",
                  key_header="X-OTX-API-KEY"),
    "wayback": Source(lambda a: "https://web.archive.org/cdx/search/cdx"
                                f"?url=*.{a}&output=txt&fl=original&collapse=urlkey&limit=20000",
                      text=True),
    "hackertarget": Source(lambda a: f"https://api.hackertarget.com/hostsearch/?q={a}", text=True),
    "securitytrails": Source(lambda a: f"https://api.securitytrails.com/v1/domain/{a}/subdomains",
                             key_header="APIKEY", key_required=True),
    "virustotal": Source(lambda a: f"{_VT_BASE}domains/{a}/subdomains?limit=40",
                         key_header="x-apikey", key_required=True),
}
DEFAULT_SOURCES = ["certspotter", "otx", "wayback"]


async def _read_capped(client: httpx.AsyncClient, url: str, headers: dict) -> str:
    async with client.stream("GET", url, headers=headers) as r:
        r.raise_for_status()
        buf = bytearray()
        async for chunk in r.aiter_bytes():
            buf.extend(chunk)
            if len(buf) >= _MAX_BYTES:
                log.debug("passive: corpo truncado em %d bytes", _MAX_BYTES)
                break
        return buf.decode("utf-8", errors="replace")


def _parse(name: str, body: str, apex: str) -> set[str]:
    """Nomes sob o apex. Varredura defensiva (como o collector de CT): não
    depende do formato exato da resposta, só de achar hostnames nela."""
    src = SOURCES[name]
    if src.text:
        low = body.lstrip().lower()
        # hackertarget responde 200 com texto de erro quando a cota acaba
        if low.startswith("error") or "api count exceeded" in low:
            raise ValueError("fonte respondeu erro")
        return _extract_hosts(body, apex)
    payload = json.loads(body)
    if name == "securitytrails":  # rótulos ("www"), não o nome completo
        labels = payload.get("subdomains") if isinstance(payload, dict) else None
        return {f"{lab.strip('.').lower()}.{apex}" for lab in labels or []
                if isinstance(lab, str) and lab.strip(".")}
    return _extract_hosts(payload, apex)


async def _fetch(client: httpx.AsyncClient, name: str, apex: str, key: str) -> set[str]:
    src = SOURCES[name]
    headers = {src.key_header: key} if (src.key_header and key) else {}
    body = await _read_capped(client, src.url(apex), headers)
    found = _parse(name, body, apex)
    if name == "virustotal":  # paginado: segue `links.next`, só dentro da própria API
        nxt = (json.loads(body).get("links") or {}).get("next")
        for _ in range(_VT_MAX_PAGES - 1):
            if not (isinstance(nxt, str) and nxt.startswith(_VT_BASE)):
                break   # nunca manda a chave para outro host
            body = await _read_capped(client, nxt, headers)
            found |= _parse(name, body, apex)
            nxt = (json.loads(body).get("links") or {}).get("next")
    return found


async def query_sources(apex: str, sources: list[str], keys: dict[str, str],
                        timeout: float, transport: httpx.AsyncBaseTransport | None = None,
                        ) -> tuple[set[str], dict[str, str]]:
    """Consulta as fontes EM PARALELO. Devolve (nomes sob o apex, status por
    fonte). Uma fonte que falha não derruba as outras. `timeout` é o prazo
    TOTAL de cada fonte (o do httpx vale por operação: uma resposta que chega
    devagar, aos pedaços, passaria dele). `transport`: injeção p/ testes."""

    async def one(client: httpx.AsyncClient, name: str) -> tuple[str, set[str]]:
        src = SOURCES.get(name)
        if src is None:
            return "desconhecida", set()
        key = (keys or {}).get(name, "")
        if src.key_required and not key:
            return "sem chave", set()
        try:
            got = await asyncio.wait_for(_fetch(client, name, apex, key), timeout)
        except asyncio.TimeoutError:
            return "erro (prazo esgotado)", set()
        except Exception as exc:  # noqa: BLE001 — fonte externa: falha é esperada
            return f"erro ({type(exc).__name__})", set()
        return f"{len(got)} nome(s)", got

    names: set[str] = set()
    status: dict[str, str] = {}
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": _USER_AGENT},
                                 follow_redirects=False, transport=transport) as client:
        results = await asyncio.gather(*(one(client, n) for n in sources))
    for name, (st, got) in zip(sources, results):
        status[name] = st
        names |= got
    names.discard(apex)
    return names, status


async def collect(target: str, sources: list[str], keys: dict[str, str], timeout: float,
                  dns_timeout: float, concurrency: int = 50, wildcard=None, pace=None,
                  skip: set[str] | None = None, max_candidates: int = 2000,
                  transport: httpx.AsyncBaseTransport | None = None) -> CollectionResult:
    """Nomes das fontes passivas que RESOLVEM agora. `skip`: nomes já
    conhecidos/descobertos neste scan (não precisam ser resolvidos de novo).
    `ok` = pelo menos uma fonte respondeu."""
    apex = target.lower().lstrip(".")
    names, status = await query_sources(apex, sources, keys, timeout, transport)
    answered = any(v.endswith("nome(s)") for v in status.values())
    candidates = sorted(names - (skip or set()))
    if len(candidates) > max_candidates:
        log.warning("[%s] fontes passivas: %d candidatos novos, resolvendo só os %d primeiros "
                    "(collectors.passive_max_candidates).", target, len(candidates), max_candidates)
        candidates = candidates[:max_candidates]
    found = await resolve_hosts(candidates, dns_timeout, concurrency, wildcard, pace) or set()
    log.info("[%s] fontes passivas: %s -> %d candidato(s) novo(s), %d resolvem",
             target, ", ".join(f"{k} {v}" for k, v in status.items()) or "nenhuma",
             len(candidates), len(found))
    records = [Record(Kind.SUBDOMAIN, h) for h in sorted(found)]
    return CollectionResult(records=records, ok=answered, hosts=found)
