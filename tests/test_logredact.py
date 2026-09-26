"""P0.1 — segredos nunca aparecem no log (redação)."""

import logging

from padme.logredact import RedactionFilter, install_secret_redaction, redact

# strings de teste (NÃO são segredos reais)
_TG = "bot123456789:AA_TOKEN_TESTE_SUPER_SECRETO_abcdefghijklmnop"
_DISCORD = "https://discord.com/api/webhooks/1122334455/WEBHOOK_SECRET_TESTE_abcdefghijklmnop"


def test_redact_token_telegram():
    out = redact(f"HTTP Request: POST https://api.telegram.org/{_TG}/sendMessage")
    assert "TOKEN_TESTE_SUPER_SECRETO" not in out
    assert "bot123456789:REDACTED" in out


def test_redact_webhook_discord():
    out = redact(f"POST {_DISCORD}")
    assert "WEBHOOK_SECRET_TESTE" not in out
    assert "/webhooks/1122334455/REDACTED" in out


def test_redact_authorization_e_query():
    assert "TOKEN_TESTE_SUPER_SECRETO" not in redact("Authorization: Bearer TOKEN_TESTE_SUPER_SECRETO")
    assert "abc123secreto" not in redact("GET https://api.x/v1?token=abc123secreto&page=1")


def test_filtro_mascara_logrecord(caplog):
    logger = logging.getLogger("padme.test.redact")
    logger.addFilter(RedactionFilter())
    with caplog.at_level(logging.INFO, logger="padme.test.redact"):
        logger.info("enviando via %s", _TG)  # segredo entra por args
    texto = "\n".join(r.getMessage() for r in caplog.records)
    assert "TOKEN_TESTE_SUPER_SECRETO" not in texto
    assert "REDACTED" in texto


def test_install_sobe_httpx_para_warning():
    install_secret_redaction()
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING


def test_redact_idempotente():
    once = redact(f"POST {_DISCORD}")
    assert redact(once) == once
