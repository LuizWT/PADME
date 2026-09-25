"""Testes do lock de instância única (flock)."""

import pytest

from padme.singleton import AlreadyRunning, single_instance


def test_lock_exclui_segunda_instancia(tmp_path):
    lock = str(tmp_path / "padme.lock")
    with single_instance(lock):
        # segunda aquisição do mesmo lock deve falhar enquanto a 1ª está ativa
        with pytest.raises(AlreadyRunning):
            with single_instance(lock):
                pass


def test_lock_reutilizavel_apos_liberar(tmp_path):
    lock = str(tmp_path / "padme.lock")
    with single_instance(lock):
        pass
    # liberado -> dá pra adquirir de novo sem erro
    with single_instance(lock):
        pass
