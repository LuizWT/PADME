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
    for cmd in ("scan", "monitor", "events", "export", "web", "doctor", "health"):
        args = parser.parse_args([cmd])
        assert hasattr(args, "func")


def test_test_notify_foi_removido(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["test-notify"])
    assert "erro" in capsys.readouterr().err


def test_sem_subcomando_vira_monitor_no_main():
    # o parser aceita vazio; quem decide que vazio = monitor é o main()
    assert build_parser().parse_args([]).command is None


def test_monitor_once_e_lock():
    parser = build_parser()
    args = parser.parse_args(["monitor", "--once", "--lock", "/tmp/x.lock"])
    assert args.once is True
    assert args.lock == "/tmp/x.lock"
    # padrão: sem --once/--lock
    d = parser.parse_args(["monitor"])
    assert d.once is False and d.lock is None
