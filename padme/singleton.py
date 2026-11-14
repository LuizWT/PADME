"""Instância única via lock de arquivo — multiplataforma.

Uso típico: cron/agendador chama `padme monitor --once --lock /tmp/padme.lock`
de N em N minutos. Se um ciclo anterior ainda estiver rodando (alvo lento, rede
travada), a nova invocação detecta o lock e sai sem sobrepor.

- Unix/Linux/macOS: `fcntl.flock` (lock exclusivo, não-bloqueante).
- Windows: `msvcrt.locking` (trava 1 byte do arquivo, não-bloqueante).
- Sem nenhum dos dois: vira no-op COM AVISO — melhor rodar sem lock do que não
  rodar; a doc deixa claro que aí não há exclusão.
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import contextmanager
from typing import IO

log = logging.getLogger("padme")

# `sys.platform` (e não try/except) para o verificador de tipos saber qual
# módulo existe em cada sistema.
_MODE: str | None
if sys.platform == "win32":  # pragma: no cover — só roda no Windows
    try:
        import msvcrt

        _MODE = "msvcrt"
    except ImportError:
        _MODE = None
else:
    try:
        import fcntl

        _MODE = "fcntl"
    except ImportError:  # pragma: no cover — POSIX sem fcntl
        _MODE = None


class AlreadyRunning(RuntimeError):
    """Outra instância já segura o lock."""


def _acquire(fh: IO[str]) -> None:
    """Adquire o lock exclusivo não-bloqueante; levanta OSError se ocupado."""
    if sys.platform == "win32":  # pragma: no cover — só roda no Windows
        if _MODE == "msvcrt":
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    elif _MODE == "fcntl":
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(fh: IO[str]) -> None:
    if sys.platform == "win32":  # pragma: no cover — só roda no Windows
        if _MODE == "msvcrt":
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
    elif _MODE == "fcntl":
        fcntl.flock(fh, fcntl.LOCK_UN)


@contextmanager
def single_instance(path: str):
    """Adquire o lock exclusivo em `path`; libera ao sair do bloco.

    Levanta AlreadyRunning se outra instância já o segura."""
    if _MODE is None:  # pragma: no cover
        log.warning("singleton: lock indisponível nesta plataforma — seguindo SEM "
                    "exclusão (%s)", path)
        yield
        return

    fh = open(path, "a+", encoding="utf-8")
    try:
        _acquire(fh)
    except OSError as exc:
        fh.close()
        raise AlreadyRunning(f"já há uma instância rodando (lock: {path})") from exc

    try:
        try:
            fh.seek(0)
            fh.write(f"{os.getpid()}\n")
            fh.flush()
        except OSError:
            pass  # gravar o PID é só informativo; não impede o lock
        yield
    finally:
        try:
            _release(fh)
        finally:
            fh.close()
