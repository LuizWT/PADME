"""Onde o Padmé guarda config e dados, por sistema operacional.

Com o comando `padme` disponível em qualquer pasta (instalador), o config não
pode depender do diretório atual. Ordem de busca do config:

  1. `-c/--config` explícito
  2. variável `PADME_CONFIG`
  3. `config.yaml` na pasta atual (compatível com o uso antigo e com o Docker)
  4. pasta do usuário: Windows `%APPDATA%\\padme\\config.yaml`,
     Linux/macOS `~/.config/padme/config.yaml` (ou `$XDG_CONFIG_HOME/padme`)

O banco (`db_path` relativo) e o `.env` ficam ao lado do config.
"""

from __future__ import annotations

import os
from pathlib import Path

APP = "padme"


def config_dir() -> Path:
    """Pasta de config do usuário (não precisa existir)."""
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP


def data_dir() -> Path:
    """Pasta de dados do usuário (estado do `--update`)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP


def find_config(explicit: str | None = None) -> Path:
    """Config a usar, pela ordem do docstring do módulo. Não exige que exista:
    quem chama decide entre erro e `padme init`."""
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("PADME_CONFIG", "").strip()
    if env:
        return Path(env).expanduser()
    local = Path("config.yaml")
    if local.is_file():
        return local
    return config_dir() / "config.yaml"
