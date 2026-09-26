"""Redação de segredos nos logs.

Duas linhas de defesa:
  1. `httpx`/`httpcore` sobem para WARNING — some a request line
     ("HTTP Request: POST https://api.telegram.org/bot<TOKEN>/...") que é o
     principal vetor de vazamento quando se roda com `-v`.
  2. Um `RedactionFilter` no root mascara segredos conhecidos em QUALQUER
     mensagem logada (defesa em profundidade), então mesmo um log próprio
     descuidado não vaza token/secret.

O que é mascarado: bot token do Telegram, secret de webhook do Discord,
header Authorization/Bearer, e query params sensíveis (token/key/secret/...).
Nunca reproduzimos o segredo — sempre trocamos por REDACTED.
"""

from __future__ import annotations

import logging
import re

_REDACTED = "REDACTED"

# Cada par (regex, substituição). A substituição preserva a parte pública
# (ex.: mantém "bot" e o id numérico do webhook) e some com o segredo.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Telegram: .../bot<digits>:<token>/...  -> mantém o prefixo, mascara o token
    (re.compile(r"(bot\d+):[A-Za-z0-9_\-]{20,}"), r"\1:" + _REDACTED),
    # Telegram token cru (digits:token) sem o "bot"
    (re.compile(r"\b(\d{6,}):[A-Za-z0-9_\-]{30,}\b"), r"\1:" + _REDACTED),
    # Discord/qualquer webhook: /webhooks/<id>/<secret> -> mantém o id
    (re.compile(r"(/webhooks/\d+)/[A-Za-z0-9_\-\.]{20,}"), r"\1/" + _REDACTED),
    # Authorization: [Bearer] <token>  -> mascara o valor inteiro
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?\S+"), r"\1" + _REDACTED),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9_\-\.=]+"), r"\1" + _REDACTED),
    # Query params sensíveis: ?token=...  &api_key=...  &secret=...  &signature=...
    (re.compile(r"(?i)([?&](?:token|api[_-]?key|key|secret|signature|sig|access[_-]?token|auth)=)[^&\s]+"),
     r"\1" + _REDACTED),
    # userinfo em URL: scheme://user:pass@host
    (re.compile(r"(://[^/:\s]+):[^@/\s]+@"), r"\1:" + _REDACTED + "@"),
]


def redact(text: str) -> str:
    """Mascara segredos conhecidos em um texto. Idempotente e defensivo."""
    if not text:
        return text
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


class RedactionFilter(logging.Filter):
    """Filtro que reescreve a mensagem já formatada, mascarando segredos.

    Reescreve `record.msg` com a mensagem interpolada e zera `record.args`
    para não reinterpolar — assim segredos vindos por args também são cobertos.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - formatação exótica
            return True
        clean = redact(msg)
        if clean != msg or record.args:
            record.msg = clean
            record.args = ()
        return True


def install_secret_redaction(quiet_http: bool = True) -> None:
    """Instala as duas defesas. Idempotente (não duplica o filtro)."""
    if quiet_http:
        for name in ("httpx", "httpcore", "httpcore.http11", "httpcore.connection"):
            logging.getLogger(name).setLevel(logging.WARNING)

    root = logging.getLogger()
    if not any(isinstance(f, RedactionFilter) for f in root.filters):
        root.addFilter(RedactionFilter())
    # Também nos handlers: um filtro no logger não se aplica a registros que
    # sobem de loggers-filhos direto pra um handler; cobrir os handlers fecha isso.
    for h in root.handlers:
        if not any(isinstance(f, RedactionFilter) for f in h.filters):
            h.addFilter(RedactionFilter())
