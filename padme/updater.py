"""`padme --update`: atualiza para a versão mais recente do GitHub.

Leve de propósito (só stdlib): roda antes de carregar config e collectors.

  - instalação normal (instalador ou `pip install`): baixa o .zip do commit
    mais recente do `main` (não precisa de git) e reinstala o pacote; depois
    instala só as dependências que faltarem;
  - instalação a partir de um clone (`pip install -e .`): `git pull` no clone;
  - Docker: avisa que a atualização é pela imagem.

Guarda o commit instalado para responder "já está atualizado" sem baixar nada.
No Windows, quem roda pelo `padme.exe` não pode ter o próprio .exe trocado
enquanto ele executa: a atualização continua num processo filho.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import __version__
from .paths import data_dir

REPO = "LuizWT/PADME"
BRANCH = "main"
DIST = "padme-asm"
_API = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"
_STATE = "update.json"
_CHILD_ENV = "PADME_UPDATE_CHILD"


def archive_url(ref: str) -> str:
    return f"https://github.com/{REPO}/archive/{ref}.zip"


def latest_commit(timeout: float = 10.0) -> str | None:
    """SHA do commit mais recente do main, ou None (sem rede, limite da API)."""
    req = urllib.request.Request(_API, headers={"Accept": "application/vnd.github+json",
                                                "User-Agent": f"padme/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            sha = json.loads(r.read().decode("utf-8")).get("sha")
    except Exception:  # noqa: BLE001 — sem a resposta, atualiza pelo nome do branch
        return None
    return sha if isinstance(sha, str) and len(sha) == 40 else None


def install_kind() -> tuple[str, Path | None]:
    """('editable', clone) | ('pip', None) | ('source', pasta) — de onde o
    pacote está rodando, pelo direct_url.json que o pip grava (PEP 610)."""
    from importlib import metadata
    try:
        dist = metadata.distribution(DIST)
    except metadata.PackageNotFoundError:
        return "source", Path(__file__).resolve().parent.parent
    raw = dist.read_text("direct_url.json")
    if raw:
        try:
            info = json.loads(raw)
        except ValueError:
            info = {}
        if (info.get("dir_info") or {}).get("editable"):
            url = info.get("url", "")
            if url.startswith("file://"):
                from urllib.parse import unquote, urlparse
                p = unquote(urlparse(url).path)
                if os.name == "nt" and p.startswith("/") and ":" in p[:4]:
                    p = p[1:]   # /C:/... -> C:/...
                return "editable", Path(p)
    return "pip", None


def _state_file() -> Path:
    return data_dir() / _STATE


def installed_commit() -> str | None:
    try:
        return json.loads(_state_file().read_text(encoding="utf-8")).get("sha")
    except Exception:  # noqa: BLE001
        return None


def _save_commit(sha: str) -> None:
    try:
        f = _state_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"sha": sha, "at": int(time.time())}), encoding="utf-8")
    except OSError:
        pass   # sem onde gravar: só perde o "já está atualizado" da próxima vez


def _pip(*args: str) -> int:
    cmd = [sys.executable, "-m", "pip", "--disable-pip-version-check", *args]
    return subprocess.call(cmd)


def _in_docker() -> bool:
    return Path("/.dockerenv").exists()


def _running_from_exe() -> bool:
    return os.name == "nt" and Path(sys.argv[0]).suffix.lower() == ".exe"


def run(force: bool = False) -> int:
    if _in_docker():
        print("Na imagem Docker a atualização é pela imagem:\n"
              "  docker compose build --pull && docker compose up -d")
        return 1

    kind, where = install_kind()
    if kind in ("editable", "source"):
        if where and (where / ".git").exists():
            print(f"Instalação a partir do clone em {where}: atualizando com git pull.")
            rc = subprocess.call(["git", "-C", str(where), "pull", "--ff-only"])
            if rc != 0:
                print("git pull falhou (alterações locais ou git ausente). Nada foi mudado.")
                return rc
            if kind == "editable":   # dependências novas, se houver
                return _pip("install", "--quiet", "-e", str(where))
            return 0
        print("Este Padmé não foi instalado pelo pip nem por um clone git; reinstale\n"
              "com o instalador (install.bat no Windows, install.sh no Linux).")
        return 1

    sha = latest_commit()
    if sha and sha == installed_commit() and not force:
        print(f"Já está na versão mais recente (commit {sha[:7]}).")
        return 0

    if _running_from_exe() and not os.environ.get(_CHILD_ENV):
        # o Windows não deixa o pip trocar o padme.exe que está rodando
        print("Atualizando em segundo plano; o resultado aparece nesta janela em instantes.")
        env = {**os.environ, _CHILD_ENV: "1"}
        args = [sys.executable, "-m", "padme", "--update"] + (["--force"] if force else [])
        subprocess.Popen(args, env=env)
        return 0
    if os.environ.get(_CHILD_ENV):
        time.sleep(2)   # dá tempo do padme.exe que nos chamou terminar

    ref = sha or BRANCH
    print(f"Baixando o Padmé ({'commit ' + sha[:7] if sha else 'branch ' + BRANCH}) do GitHub...")
    # 1) o pacote, mesmo com o mesmo número de versão (o código mudou); 2) só as
    # dependências que faltarem — sem reinstalar as que estão em uso.
    rc = _pip("install", "--quiet", "--upgrade", "--force-reinstall", "--no-deps",
              archive_url(ref))
    if rc != 0:
        print("Falha ao baixar/instalar a versão nova. A versão atual continua instalada.")
        return rc
    reqs = subprocess.run(
        [sys.executable, "-c",
         f"from importlib.metadata import requires; print('\\n'.join(requires('{DIST}') or []))"],
        capture_output=True, text=True).stdout.split("\n")
    reqs = [r.strip() for r in reqs if r.strip() and "extra ==" not in r]
    if reqs and _pip("install", "--quiet", *reqs) != 0:
        print("Pacote atualizado, mas alguma dependência falhou: rode `padme --update --force`.")
        return 1
    if sha:
        _save_commit(sha)
    print("Atualizado. Se o Padmé estiver rodando, reinicie-o para usar a versão nova.")
    return 0
