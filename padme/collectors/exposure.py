"""Checagens HTTP fixas para arquivos e endpoints publicados por engano.

O coletor é deliberadamente pequeno: só lê os caminhos da base curada, faz GET
sem parâmetros, limita cada corpo a 4 KiB e nunca persiste conteúdo de resposta.
"""
from __future__ import annotations

import json
import re
import secrets
from functools import lru_cache
from importlib import resources

import httpx

from ..models import CollectionResult, Kind, Record
from ..targets import url_host
from .http import _fetch_limited

MAX_BYTES = 4096
_SOFT404_PREFIX = "/.__padme_soft404_"
_LOGIN_RE = re.compile(r"(?is)<title>\s*(?:login|sign in|entrar)\b|(?:name|id)=['\"](?:login|password|senha)")


def _load_checks() -> tuple[dict, ...]:
    raw = resources.files("padme").joinpath("data/exposures.json").read_text("utf-8")
    return tuple(json.loads(raw)["checks"])


CHECKS = _load_checks()


@lru_cache(maxsize=256)
def _regex(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def _content_type(headers: httpx.Headers) -> str:
    return (headers.get("content-type", "").split(";", 1)[0].strip().lower())


def _matches(check: dict, body: str, content_type: str) -> bool:
    sig = check["signature"]
    allowed = {str(x).lower() for x in sig.get("content_types", [])}
    if allowed and content_type not in allowed:
        return False
    if "contains" in sig:
        return str(sig["contains"]).lower() in body.lower()
    return bool(_regex(str(sig["regex"])).search(body))


def _is_login_redirect(status: int, body: str) -> bool:
    # Redirects são vistos sem armazenar seu corpo; quando a política permite
    # segui-los, o HTML final ainda não pode transformar uma tela de login em
    # exposição.
    return status in range(300, 400) or bool(_LOGIN_RE.search(body))


async def _get(client: httpx.AsyncClient, host: str, path: str,
               follow_redirects: bool, allow_private: bool) -> tuple[int, str, str] | None:
    try:
        response, body = await _fetch_limited(
            client, f"https://{url_host(host)}{path}", follow_redirects, MAX_BYTES,
            allow_private,
        )
        return response.status_code, _content_type(response.headers), body
    except Exception:
        try:
            response, body = await _fetch_limited(
                client, f"http://{url_host(host)}{path}", follow_redirects, MAX_BYTES,
                allow_private,
            )
            return response.status_code, _content_type(response.headers), body
        except Exception:
            return None


async def collect_host(host: str, client: httpx.AsyncClient,
                       follow_redirects: bool = False,
                       allow_private: bool = False) -> CollectionResult:
    """Sonda a lista fixa e retorna apenas metadados não sensíveis.

    `ok=False` quando qualquer GET fica inconclusivo; assim o escopo por host
    preserva achados anteriores em vez de resolver problemas por timeout.
    """
    # Uma resposta 200 idêntica no caminho aleatório identifica soft-404.
    soft_path = f"{_SOFT404_PREFIX}{secrets.token_hex(8)}"
    soft = await _get(client, host, soft_path, follow_redirects, allow_private)
    if soft is None:
        return CollectionResult(ok=False)
    soft_status, _, soft_body = soft
    soft404_body = soft_status == 200 and soft_body
    records: list[Record] = []
    complete = True
    for check in CHECKS:
        observed = await _get(client, host, check["path"], follow_redirects, allow_private)
        if observed is None:
            complete = False
            continue
        status, content_type, body = observed
        # Status 200 nunca é suficiente. Redirect/login também não é exposição.
        is_soft = bool(soft404_body and status == 200 and body == soft_body)
        strong = bool(check["signature"].get("strong", False))
        if status != 200 or _is_login_redirect(status, body) or (is_soft and not strong):
            continue
        if not _matches(check, body, content_type):
            continue
        size = min(MAX_BYTES, len(body.encode("utf-8", errors="ignore")))
        md = {
            "exposure_id": check["id"],
            "path": check["path"],
            "signature": check["id"],
            "status": status,
            "content_type": content_type,
            "size": size,
            "severity": check["severity"],
            "description": check["description"],
            "remediation": check["remediation"],
            "soft_404": bool(is_soft),
        }
        # Value também é deliberadamente redigido: nunca inclui body/segredo.
        value = f"{check['id']} | {check['path']} | HTTP {status}"
        records.append(Record(Kind.EXPOSURE, f"{host}|{check['id']}", value, md))
    return CollectionResult(records=records, ok=complete)
