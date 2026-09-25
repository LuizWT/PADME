"""Smoke tests do CLI — o entrypoint empacotado (`padme = padme.cli:main`).

Garante que o parser monta e os subcomandos esperados existem, protegendo o
console_script usado por `pipx install` e pela imagem Docker.
"""

import pytest

from padme import __version__
from padme.cli import build_parser


def test_version_action(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_subcomandos_esperados():
    parser = build_parser()
    for cmd in ("scan", "monitor", "events", "export", "test-notify", "web"):
        args = parser.parse_args([cmd])
        assert hasattr(args, "func")


def test_sem_subcomando_exige_um(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_monitor_once_e_lock():
    parser = build_parser()
    args = parser.parse_args(["monitor", "--once", "--lock", "/tmp/x.lock"])
    assert args.once is True
    assert args.lock == "/tmp/x.lock"
    # padrão: sem --once/--lock
    d = parser.parse_args(["monitor"])
    assert d.once is False and d.lock is None
