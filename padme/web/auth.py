"""Autenticação do painel: token Bearer, login Basic do navegador e checagem de
origem das ações. Comparações em tempo constante.
"""

from __future__ import annotations

import base64
import hmac
import urllib.parse


def _bearer_ok(header: str | None, token: str) -> bool:
    """Valida `Authorization: Bearer <token>` em tempo constante.

    Header ausente/malformado -> False. Comparação com `hmac.compare_digest`
    (não vaza o tamanho/prefixo do token por timing). Chamado só quando há token
    configurado."""
    if not header:
        return False
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    # compara em bytes: cabeçalhos chegam decodificados em latin-1, e
    # compare_digest levanta TypeError com str não-ASCII — encode fecha isso
    # (mantém tempo constante) e nunca deixa a exceção escapar como 500.
    return hmac.compare_digest(parts[1].strip().encode("utf-8"), token.encode("utf-8"))


def _auth_ok(header: str | None, token: str) -> bool:
    """Aceita `Bearer <token>` (curl/automação) OU `Basic` — o que o NAVEGADOR
    envia sozinho depois do prompt de login (usuário qualquer, senha = token).
    Tempo constante nos dois; qualquer coisa malformada -> False (nunca 500)."""
    if not header:
        return False
    parts = header.split(None, 1)
    if len(parts) != 2:
        return False
    scheme = parts[0].lower()
    if scheme == "bearer":
        return _bearer_ok(header, token)
    if scheme != "basic":
        return False
    try:
        raw = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
    except Exception:  # noqa: BLE001 — base64/utf-8 inválido
        return False
    _user, sep, password = raw.partition(":")
    if not sep:
        return False
    return hmac.compare_digest(password.encode("utf-8"), token.encode("utf-8"))


def _same_origin(headers) -> bool:
    """CSRF em camadas, além do token: navegador moderno manda `Sec-Fetch-Site`
    e/ou `Origin` num POST — origem cruzada (ou opaca, 'null') é recusada. Sem
    nenhum dos dois (curl, navegador antigo) quem decide é o token de CSRF."""
    site = headers.get("Sec-Fetch-Site")
    if site and site not in ("same-origin", "none"):
        return False
    origin = headers.get("Origin")
    if origin is None:
        return True
    if origin == "null":
        return False
    return urllib.parse.urlparse(origin).netloc == (headers.get("Host") or "")


def _basic_user(header: str | None) -> str:
    """Usuário do login Basic (vai para a trilha de auditoria); '' se não houver."""
    parts = (header or "").split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "basic":
        return ""
    try:
        raw = base64.b64decode(parts[1].strip(), validate=True).decode("utf-8")
    except Exception:  # noqa: BLE001 — já validado pelo _auth_ok; aqui só o nome
        return ""
    return raw.partition(":")[0].strip()
