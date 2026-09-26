"""§32/§33/§34 — validação forte de config, normalização de alvo, bool robusto."""

import os
import tempfile

import pytest

from padme.config import Config, _normalize_target


def _load(text: str) -> Config:
    p = tempfile.mktemp(suffix=".yaml")
    open(p, "w", encoding="utf-8").write(text)
    try:
        return Config.load(p)
    finally:
        os.remove(p)


# ── §32 normalização de alvo ────────────────────────────────────────────────
def test_normalize_target_formas():
    assert _normalize_target("https://Example.COM/path?q=1") == "example.com"
    assert _normalize_target("EXEMPLO.COM.") == "exemplo.com"
    assert _normalize_target("*.alvo.com") == "alvo.com"
    assert _normalize_target("site.com:443") == "site.com"


def test_normalize_target_idn():
    assert _normalize_target("café.com") == "xn--caf-dma.com"


def test_normalize_target_invalido():
    for bad in ("", "semponto", "http://", "-x.com"):
        with pytest.raises(ValueError):
            _normalize_target(bad)


def test_targets_normalizados_e_dedup():
    cfg = _load("targets:\n  - https://X.com/a\n  - x.com\n  - api.y.com\n")
    assert cfg.targets == ["x.com", "api.y.com"]     # normalizado + dedup, ordem preservada


def test_alvo_invalido_falha():
    with pytest.raises(ValueError):
        _load("targets: [not_a_domain]\n")


# ── §34 bool robusto ────────────────────────────────────────────────────────
def test_bool_string_false_nao_vira_true():
    cfg = _load("targets: [x.com]\ncollectors: {ports: 'false'}\n")
    assert cfg.collectors.ports is False


def test_bool_invalido_falha():
    with pytest.raises(ValueError):
        _load("targets: [x.com]\ncollectors: {ports: talvez}\n")


# ── §33 validação de faixas ─────────────────────────────────────────────────
@pytest.mark.parametrize("snippet", [
    "interval_seconds: 0",
    "concurrency: -5",
    "timeout: -1",
    "collectors: {wildcard_probes: 1}",
    "collectors: {cert_expiry_days: -500}",
    "collectors: {ports_list: [22, 70000]}",
    "collectors: {max_response_bytes: 0}",
    "storage: {event_retention_days: -3}",
    "email: {smtp_port: 0}",
    "telegram: {level: lixo}",
])
def test_config_invalida_falha_cedo(snippet):
    with pytest.raises(ValueError):
        _load(f"targets: [x.com]\n{snippet}\n")


def test_inteiro_invalido_falha():
    with pytest.raises(ValueError):
        _load("targets: [x.com]\nconcurrency: abc\n")


# ── config válida carrega + source default = hostname ───────────────────────
def test_valida_carrega_com_source():
    cfg = _load("targets: [x.com]\nconcurrency: 20\n")
    assert cfg.concurrency == 20
    assert cfg.source and isinstance(cfg.source, str)   # default = hostname


def test_source_explicito():
    cfg = _load("targets: [x.com]\nsource: vps-eu\n")
    assert cfg.source == "vps-eu"
