"""`padme service`: o Padmé rodando 24/7 no Windows, sem terminal aberto.

Registra uma tarefa no Agendador de Tarefas do Windows que:

- inicia o monitor quando você entra no Windows (e já agora, no `install`);
- roda escondida, pelo `pythonw.exe` do ambiente do Padmé (sem janela);
- grava o log em `padme.log`, ao lado do config (sem janela, não há terminal);
- reinicia sozinha se o processo cair (a cada minuto);
- usa a trava de instância única (`padme.lock`): nunca dois monitores.

Roda com o seu usuário e só enquanto você estiver logado: não pede senha nem
administrador. No Linux, o equivalente é o systemd (docs/RUNBOOK.md).

A montagem do XML e do comando é pura e testável fora do Windows; quem chama o
`schtasks` recebe a função de execução (`run`) por parâmetro.
"""

from __future__ import annotations

import csv
import io
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

TASK_NAME = "Padme"
DESCRIPTION = "Padmé: monitor da superfície de ataque (padme service)"

Runner = Callable[..., Any]


def log_path(config_path: Path) -> Path:
    return config_path.parent / "padme.log"


def lock_path(config_path: Path) -> Path:
    return config_path.parent / "padme.lock"


def _pythonw() -> Path:
    """O `pythonw.exe` do ambiente do Padmé (roda sem console). Sem ele, o
    `python.exe` (abre uma janela, mas funciona)."""
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return w if w.exists() else exe


def monitor_command(config_path: Path, no_web: bool = False,
                    python: Path | None = None) -> tuple[str, list[str]]:
    """(executável, argumentos) que a tarefa roda: o monitor com log em arquivo
    e trava de instância única."""
    cfg = config_path.resolve()
    args = ["-m", "padme", "-c", str(cfg), "monitor",
            "--log-file", str(log_path(cfg)), "--lock", str(lock_path(cfg))]
    if no_web:
        args.append("--no-web")
    return str(python or _pythonw()), args


def current_user() -> str:
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    domain = os.environ.get("USERDOMAIN") or ""
    return f"{domain}\\{user}" if domain and user else user


def task_xml(user: str, command: str, arguments: list[str], workdir: str) -> str:
    """Definição da tarefa (schema 1.2 do Agendador de Tarefas): logon do
    usuário, sem limite de tempo, reinício em caso de falha, sem depender de
    bateria nem de rede."""
    e = escape
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{e(DESCRIPTION)}</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{e(user)}</UserId>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{e(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{e(command)}</Command>
      <Arguments>{e(subprocess.list2cmdline(arguments))}</Arguments>
      <WorkingDirectory>{e(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _schtasks(run: Runner, *args: str) -> Any:
    return run(["schtasks", *args], capture_output=True, text=True)


def _out(r: Any) -> str:
    return ((r.stdout or "") + (r.stderr or "")).strip()


def install(config_path: Path, no_web: bool = False, start: bool = True,
            run: Runner = subprocess.run) -> int:
    if not config_path.is_file():
        print(f"Config não encontrado em {config_path}. Crie com: padme init", file=sys.stderr)
        return 2
    command, args = monitor_command(config_path, no_web)
    xml = task_xml(current_user(), command, args, str(config_path.resolve().parent))
    fd, tmp = tempfile.mkstemp(prefix="padme-task-", suffix=".xml")
    os.close(fd)
    try:
        Path(tmp).write_text(xml, encoding="utf-16")   # o schtasks espera UTF-16
        r = _schtasks(run, "/Create", "/TN", TASK_NAME, "/XML", tmp, "/F")
    finally:
        Path(tmp).unlink(missing_ok=True)
    if r.returncode != 0:
        print(f"Não consegui registrar a tarefa:\n{_out(r)}", file=sys.stderr)
        if "acesso negado" in _out(r).lower() or "access is denied" in _out(r).lower():
            print("Se a sua conta não puder criar tarefas, abra o terminal como "
                  "administrador uma vez e rode de novo.", file=sys.stderr)
        return 1
    print(f"Tarefa \"{TASK_NAME}\" registrada: o Padmé roda sozinho quando você entra no "
          "Windows, sem janela, e reinicia se cair.")
    print(f"  log:    {log_path(config_path.resolve())}")
    if not no_web:
        print("  painel: http://127.0.0.1:8787")
    if start:
        r = _schtasks(run, "/Run", "/TN", TASK_NAME)
        if r.returncode == 0:
            print("Iniciado agora. Para conferir: padme service status")
        else:
            print(f"Registrada, mas não iniciou agora ({_out(r)}). Ela inicia no próximo logon.")
    print("Com o serviço ligado, não rode outro `padme` à mão: use o painel ou `padme scan`.")
    return 0


def status(config_path: Path, run: Runner = subprocess.run) -> int:
    r = _schtasks(run, "/Query", "/TN", TASK_NAME, "/FO", "CSV", "/NH")
    if r.returncode != 0:
        print(f"Tarefa \"{TASK_NAME}\" não instalada. Para instalar: padme service install")
        return 1
    rows = [row for row in csv.reader(io.StringIO(r.stdout or "")) if row]
    state = rows[0][2] if rows and len(rows[0]) >= 3 else "?"
    print(f"Tarefa \"{TASK_NAME}\": {state}")      # texto do Windows, no idioma dele
    print(f"  log: {log_path(config_path.resolve())}")
    return 0


def uninstall(run: Runner = subprocess.run) -> int:
    _schtasks(run, "/End", "/TN", TASK_NAME)       # para o monitor, se estiver rodando
    r = _schtasks(run, "/Delete", "/TN", TASK_NAME, "/F")
    if r.returncode != 0:
        print(f"Tarefa \"{TASK_NAME}\" não estava instalada.")
        return 0
    print(f"Tarefa \"{TASK_NAME}\" removida: o Padmé não inicia mais sozinho.")
    return 0


def main(action: str, config_path: Path, no_web: bool = False, start: bool = True,
         run: Runner = subprocess.run, platform: str = sys.platform) -> int:
    if platform != "win32":
        print("`padme service` é para Windows. No Linux, use o systemd: "
              "https://github.com/LuizWT/PADME/blob/main/docs/RUNBOOK.md#1-systemd-sentinela-247",
              file=sys.stderr)
        return 2
    if action == "install":
        return install(config_path, no_web=no_web, start=start, run=run)
    if action == "status":
        return status(config_path, run=run)
    return uninstall(run=run)
