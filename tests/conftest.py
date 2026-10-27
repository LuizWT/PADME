"""Configuração comum dos testes."""

import pytest


@pytest.fixture(autouse=True)
def _sem_fontes_passivas_reais(request, monkeypatch):
    """Nenhum teste consulta certspotter/otx/wayback de verdade: rede externa no
    CI deixaria a suíte lenta e instável. Os testes das próprias fontes usam
    `@pytest.mark.passive_sources` e um `httpx.MockTransport`."""
    if request.node.get_closest_marker("passive_sources"):
        return

    async def nenhuma_fonte(apex, sources, keys, timeout, transport=None):
        return set(), {}

    monkeypatch.setattr("padme.collectors.passive.query_sources", nenhuma_fonte)
