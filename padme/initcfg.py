"""`padme init`: cria o config.yaml com algumas perguntas.

Pensado para quem acabou de instalar: pergunta os domínios, confirma a
autorização (sem ela o Padmé não varre nada) e, se quiser, o Telegram. O
token do bot vai para o `.env` ao lado do config, nunca para o YAML. O
resultado é um config curto; todas as outras opções estão documentadas em
`config.example.yaml`.

Também funciona sem perguntas (para scripts): `padme init --target a.com
--yes` cria o config com o escopo já confirmado.
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from .config import Config, _normalize_target

_TEMPLATE = """\
# Config do Padmé, criado pelo `padme init`.
# Todas as opções, comentadas: config.example.yaml no repositório.
# Monitore SOMENTE domínios seus ou que você tem autorização para testar.

scope_confirmed: {scope}

targets:
{targets}

interval_seconds: 3600     # tempo entre varreduras (segundos)
db_path: padme.db          # relativo a este arquivo

collectors:
  ports: {ports}             # varredura de portas (mais ativa)

web:
  bind: 127.0.0.1          # painel só nesta máquina
  port: 8787
{telegram}"""

_TELEGRAM = """
telegram:
  enabled: true
  bot_token: ${{PADME_TELEGRAM_TOKEN}}   # fica no .env ao lado deste arquivo
  chat_id: "{chat_id}"
  level: medium
"""


class _Closed(Exception):
    """A entrada acabou no meio das perguntas (Ctrl+D/Ctrl+Z, ou stdin que
    parece terminal mas não é: no Windows, o NUL passa no isatty)."""


def _ask(prompt: str, default: str = "") -> str:
    try:
        ans = input(prompt).strip()
    except EOFError:
        raise _Closed from None
    return ans or default


def _yes(prompt: str) -> bool:
    return _ask(f"{prompt} [s/N]: ").lower() in ("s", "sim", "y", "yes")


def _parse_targets(raw: list[str]) -> list[str]:
    out: list[str] = []
    for chunk in raw:
        for item in chunk.replace(";", ",").split(","):
            if item.strip():
                t = _normalize_target(item)
                if t not in out:
                    out.append(t)
    return out


def _write_env(env_path: Path, key: str, value: str) -> None:
    """Grava/atualiza `KEY=valor` no .env, com permissão só do dono no Linux."""
    lines = []
    if env_path.exists():
        lines = [ln for ln in env_path.read_text(encoding="utf-8").splitlines()
                 if not ln.startswith(f"{key}=")]
    lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(env_path, 0o600)


def run(path: Path, targets: list[str] | None = None, yes: bool = False,
        force: bool = False) -> int:
    try:
        return _run(path, targets, yes, force)
    except (_Closed, KeyboardInterrupt):
        print("\nConfiguração cancelada; nada foi criado. Rode `padme init` de novo quando quiser.",
              file=sys.stderr)
        return 2


def _run(path: Path, targets: list[str] | None, yes: bool, force: bool) -> int:
    path = path.expanduser()
    if path.exists() and not force:
        print(f"Já existe um config em {path}.")
        print("Use `padme init --force` para criar outro por cima.")
        return 1

    interactive = not targets and sys.stdin.isatty()
    if not targets and not interactive:
        print("Sem terminal para perguntar: use `padme init --target dominio.com --yes`.",
              file=sys.stderr)
        return 2

    print(f"Configuração do Padmé — o arquivo vai para {path}\n")
    while True:
        raw = targets or [_ask("Domínios a monitorar (separados por vírgula): ")]
        try:
            parsed = _parse_targets(raw)
        except ValueError as exc:
            if not interactive:
                print(f"Erro: {exc}", file=sys.stderr)
                return 2
            print(f"  {exc}. Tente de novo.")
            continue
        if parsed:
            break
        if not interactive:
            print("Erro: informe pelo menos um domínio.", file=sys.stderr)
            return 2
        print("  Informe pelo menos um domínio.")

    scope = yes or (interactive and _yes(
        "\nVocê é dono desses domínios ou tem AUTORIZAÇÃO para monitorá-los?"))
    ports = interactive and _yes("Ligar a varredura de portas (mais ativa, desligada por padrão)?")

    telegram = ""
    token = ""
    if interactive and _yes("Receber alertas no Telegram?"):
        try:
            token = getpass.getpass("  Token do bot (não aparece ao digitar): ").strip()
        except EOFError:
            raise _Closed from None
        chat_id = _ask("  Chat ID: ")
        if token and chat_id:
            telegram = _TELEGRAM.format(chat_id=chat_id.replace('"', ""))
        else:
            print("  Token ou chat ID vazio: Telegram fica desligado (dá para ligar depois).")
            token = ""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_TEMPLATE.format(
        scope="true" if scope else "false",
        targets="\n".join(f"  - {t}" for t in parsed),
        ports="true" if ports else "false",
        telegram=telegram), encoding="utf-8")
    if token:
        _write_env(path.parent / ".env", "PADME_TELEGRAM_TOKEN", token)
        os.environ["PADME_TELEGRAM_TOKEN"] = token
    Config.load(path)   # o que acabamos de escrever precisa carregar sem erro

    print(f"\nConfig criado: {path}")
    if not scope:
        print("Escopo NÃO confirmado: o Padmé não vai varrer nada até você colocar\n"
              f"`scope_confirmed: true` em {path}.")
    print("Pronto. Para começar a monitorar (com o painel em http://127.0.0.1:8787):  padme")
    return 0
