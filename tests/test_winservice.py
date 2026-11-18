"""`padme service` (tarefa no Agendador do Windows) e `--log-file`.

O que depende do Windows de verdade (o `schtasks` aceitar o XML, o pythonw
rodar sem janela) é testado no job windows do workflow install. Aqui: o XML,
o comando, o fluxo com um `schtasks` falso e o log em arquivo."""

import logging
import re
import sys
import xml.etree.ElementTree as ET
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import SimpleNamespace

import pytest

from padme import cli, winservice

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


@pytest.fixture
def cfg(tmp_path):
    d = tmp_path / "Minha Pasta & cia"          # espaço e & no caminho
    d.mkdir()
    p = d / "config.yaml"
    p.write_text("targets: [acme.com]\nscope_confirmed: true\n", encoding="utf-8")
    return p


def test_comando_da_tarefa(cfg):
    exe, args = winservice.monitor_command(cfg, python=Path("C:/padme/venv/Scripts/pythonw.exe"))
    assert exe.endswith("pythonw.exe")
    d = cfg.resolve().parent
    assert args == ["-m", "padme", "-c", str(cfg.resolve()), "monitor",
                    "--log-file", str(d / "padme.log"), "--lock", str(d / "padme.lock")]
    assert winservice.monitor_command(cfg, no_web=True)[1][-1] == "--no-web"


def test_xml_da_tarefa(cfg):
    exe, args = winservice.monitor_command(cfg, python=Path("C:/padme/venv/Scripts/pythonw.exe"))
    xml = winservice.task_xml("PC\\ana", exe, args, str(cfg.parent))
    root = ET.fromstring(xml.split("?>", 1)[1])            # sem a declaração UTF-16
    assert root.find("t:Triggers/t:LogonTrigger/t:UserId", NS).text == "PC\\ana"
    assert root.find("t:Principals/t:Principal/t:LogonType", NS).text == "InteractiveToken"
    assert root.find("t:Principals/t:Principal/t:RunLevel", NS).text == "LeastPrivilege"
    s = root.find("t:Settings", NS)
    assert s.find("t:ExecutionTimeLimit", NS).text == "PT0S"          # sem limite de tempo
    assert s.find("t:RestartOnFailure/t:Interval", NS).text == "PT1M"
    assert s.find("t:DisallowStartIfOnBatteries", NS).text == "false"
    assert s.find("t:MultipleInstancesPolicy", NS).text == "IgnoreNew"
    exec_ = root.find("t:Actions/t:Exec", NS)
    assert exec_.find("t:Command", NS).text == exe
    arguments = exec_.find("t:Arguments", NS).text
    assert f'"{cfg.resolve()}"' in arguments                    # caminho com espaço entre aspas
    assert "& cia" in arguments                                  # & escapado no XML, intacto ao ler


class FakeSchtasks:
    def __init__(self, fail=None, query_out='"\\Padme","N/A","Running"\n'):
        self.calls = []
        self.fail = fail or {}
        self.query_out = query_out
        self.xml = None

    def __call__(self, argv, capture_output=True, text=True):
        assert argv[0] == "schtasks"
        op = argv[1]
        self.calls.append(op)
        if op == "/Create":
            raw = Path(argv[argv.index("/XML") + 1]).read_bytes()
            assert raw[:2] in (b"\xff\xfe", b"\xfe\xff")        # UTF-16 com BOM
            self.xml = raw.decode("utf-16")
        code, out = self.fail.get(op, (0, self.query_out if op == "/Query" else ""))
        return SimpleNamespace(returncode=code, stdout=out, stderr="")


def test_install_registra_e_inicia(cfg, capsys):
    fake = FakeSchtasks()
    assert winservice.main("install", cfg, run=fake, platform="win32") == 0
    assert fake.calls == ["/Create", "/Run"]
    assert "<LogonTrigger>" in fake.xml and "--log-file" in fake.xml
    out = capsys.readouterr().out
    assert "padme.log" in out and "http://127.0.0.1:8787" in out


def test_install_sem_iniciar_e_sem_painel(cfg, capsys):
    fake = FakeSchtasks()
    assert winservice.main("install", cfg, no_web=True, start=False, run=fake,
                           platform="win32") == 0
    assert fake.calls == ["/Create"] and "--no-web" in fake.xml
    assert "8787" not in capsys.readouterr().out


def test_install_sem_permissao_explica(cfg, capsys):
    fake = FakeSchtasks(fail={"/Create": (1, "ERROR: Access is denied.")})
    assert winservice.main("install", cfg, run=fake, platform="win32") == 1
    assert "administrador" in capsys.readouterr().err


def test_install_sem_config(tmp_path, capsys):
    assert winservice.main("install", tmp_path / "nao.yaml", run=FakeSchtasks(),
                           platform="win32") == 2
    assert "padme init" in capsys.readouterr().err


def test_status_e_uninstall(cfg, capsys):
    fake = FakeSchtasks()
    assert winservice.main("status", cfg, run=fake, platform="win32") == 0
    assert 'Tarefa "Padme": Running' in capsys.readouterr().out
    assert winservice.main("uninstall", cfg, run=fake, platform="win32") == 0
    assert fake.calls[-2:] == ["/End", "/Delete"]
    nada = FakeSchtasks(fail={"/Query": (1, ""), "/Delete": (1, "")})
    assert winservice.main("status", cfg, run=nada, platform="win32") == 1
    assert "não instalada" in capsys.readouterr().out
    assert winservice.main("uninstall", cfg, run=nada, platform="win32") == 0


def test_fora_do_windows_aponta_o_systemd(cfg, capsys):
    assert winservice.main("install", cfg, run=FakeSchtasks(), platform="linux") == 2
    assert "systemd" in capsys.readouterr().err


def test_cli_service_fora_do_windows(cfg, capsys, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert cli.main(["-c", str(cfg), "service", "status"]) == 2
    assert "systemd" in capsys.readouterr().err


def test_log_file_grava_com_data_e_sem_terminal(tmp_path, monkeypatch):
    root = logging.getLogger()
    saved = (root.handlers[:], root.level)
    root.handlers = []
    try:
        monkeypatch.setattr(sys, "stderr", None)          # pythonw: não há terminal
        log = tmp_path / "sub" / "padme.log"
        cli._setup_logging(False, str(log))
        assert len(root.handlers) == 1 and isinstance(root.handlers[0], RotatingFileHandler)
        logging.getLogger("padme").info("olá do serviço")
        root.handlers[0].flush()
        text = log.read_text(encoding="utf-8")
        assert "olá do serviço" in text
        assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} INFO ", text)
    finally:
        for h in root.handlers:
            h.close()
        root.handlers, root.level = saved
