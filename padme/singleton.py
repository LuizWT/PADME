"""Instância única via lock de arquivo (flock).

Uso típico: cron chama `padme monitor --once --lock /tmp/padme.lock` de N em N
minutos. Se um ciclo anterior ainda estiver rodando (alvo lento, rede travada),
a nova invocação não sobrepõe — ela detecta o lock e sai sem fazer nada.

Baseado em `fcntl.flock` (Unix/Linux, que é o alvo do projeto/Docker). Onde
`fcntl` não existe, o lock vira no-op com aviso — melhor rodar sem lock do que
não rodar.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager

log = logging.getLogger("padme")

try:
    import fcntl

    _HAS_FCNTL = True
except Exception:  # pragma: no cover — Windows/plataformas sem fcntl
    _HAS_FCNTL = False


class AlreadyRunning(RuntimeError):
    """Outra instância já segura o lock."""


@contextmanager
def single_instance(path: str):
    """Adquire o lock exclusivo em `path`; libera ao sair do bloco.

    Levanta AlreadyRunning se outra instância já o segura."""
    if not _HAS_FCNTL:
        log.warning("singleton: fcntl indisponível — seguindo sem lock (%s)", path)
        yield
        return

    fh = open(path, "w", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        fh.close()
        raise AlreadyRunning(f"já há uma instância rodando (lock: {path})") from exc

    try:
        fh.write(f"{os.getpid()}\n")
        fh.flush()
        yield
    finally:
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        finally:
            fh.close()
