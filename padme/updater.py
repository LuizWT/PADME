"""`padme --update`: atualiza o Padmé.

Leve de propósito (só stdlib): roda antes de carregar config e collectors.

  - instalação normal (instalador ou `pip install`): instala a última versão
    publicada no PyPI; com `--dev`, o .zip do commit mais recente do `main`
    (não precisa de git). Nos dois casos reinstala só o pacote e depois só as
    dependências que faltarem, sem mexer nas que estão em uso;
  - instalação a partir de um clone (`pip install -e .`): `git pull` no clone;
  - Docker: avisa que a atualização é pela imagem.

Guarda o que instalou (versão ou commit) para responder "já está atualizado"
sem baixar nada. No Windows, quem roda pelo `padme.exe` não pode ter o próprio
.exe trocado enquanto ele executa: a atualização continua num processo filho.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .paths import data_dir

REPO = "LuizWT/PADME"
BRANCH = "main"
DIST = "padme-asm"
_API = f"https://api.github.com/repos/{REPO}/commits/{BRANCH}"
_PYPI = f"https://pypi.org/pypi/{DIST}/json"
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


def latest_release(timeout: float = 10.0) -> tuple[str, str | None]:
    """Última versão publicada no PyPI: ('ok', '0.3.0'), ('nao_publicado', None)
    ou ('erro', None) quando não deu para consultar (sem rede, PyPI fora)."""
    req = urllib.request.Request(_PYPI, headers={"Accept": "application/json",
                                                 "User-Agent": f"padme/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            info = json.loads(r.read().decode("utf-8")).get("info") or {}
    except urllib.error.HTTPError as exc:
        return ("nao_publicado", None) if exc.code == 404 else ("erro", None)
    except Exception:  # noqa: BLE001 — sem a resposta não há o que comparar
        return "erro", None
    version = info.get("version")
    return ("ok", version) if isinstance(version, str) and version else ("erro", None)


def version_key(version: str) -> tuple[int, ...]:
    """'0.10.2' -> (0, 10, 2), para comparar sem depender do `packaging`. Para no
    primeiro pedaço que não começa com número ('0.3.0rc1' -> (0, 3, 0))."""
    out: list[int] = []
    for part in version.split("."):
        digits = ""
        for ch in part:
            if not ch.isdigit():
                break
            digits += ch
        if not digits:
            break
        out.append(int(digits))
        if len(digits) < len(part):
            break
    return tuple(out)


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


def _state() -> dict[str, object]:
    try:
        data = json.loads(_state_file().read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def installed_commit() -> str | None:
    sha = _state().get("sha")
    return sha if isinstance(sha, str) else None


def _save_state(**fields: str) -> None:
    try:
        f = _state_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({**fields, "at": int(time.time())}), encoding="utf-8")
    except OSError:
        pass   # sem onde gravar: só perde o "já está atualizado" da próxima vez


def _pip(*args: str) -> int:
    cmd = [sys.executable, "-m", "pip", "--disable-pip-version-check", *args]
    return subprocess.call(cmd)


def _in_docker() -> bool:
    return Path("/.dockerenv").exists()


def _running_from_exe() -> bool:
    return os.name == "nt" and Path(sys.argv[0]).suffix.lower() == ".exe"


def _new_requirements() -> list[str]:
    """Dependências da versão recém-instalada (sem extras). Lidas num processo
    novo: este aqui ainda enxerga os metadados da versão antiga."""
    out = subprocess.run(
        [sys.executable, "-c",
         f"from importlib.metadata import requires; print('\\n'.join(requires('{DIST}') or []))"],
        capture_output=True, text=True).stdout
    return [r.strip() for r in out.split("\n") if r.strip() and "extra ==" not in r]


def _install(spec: str, label: str) -> int:
    """1) o pacote, mesmo com o mesmo número de versão; 2) só as dependências
    que faltarem, sem reinstalar as que estão em uso."""
    print(f"Baixando o Padmé ({label})...")
    rc = _pip("install", "--quiet", "--upgrade", "--force-reinstall", "--no-deps", spec)
    if rc != 0:
        print("Falha ao baixar/instalar a versão nova. A versão atual continua instalada.")
        return rc
    reqs = _new_requirements()
    if reqs and _pip("install", "--quiet", *reqs) != 0:
        print("Pacote atualizado, mas alguma dependência falhou: rode `padme --update --force`.")
        return 1
    return 0


def _continue_in_child(force: bool, dev: bool) -> bool:
    """No Windows, o pip não troca o padme.exe que está rodando: a atualização
    segue num processo filho. Devolve True se delegou."""
    if not _running_from_exe() or os.environ.get(_CHILD_ENV):
        return False
    print("Atualizando em segundo plano; o resultado aparece nesta janela em instantes.")
    env = {**os.environ, _CHILD_ENV: "1"}
    args = ([sys.executable, "-m", "padme", "--update"] + (["--force"] if force else [])
            + (["--dev"] if dev else []))
    subprocess.Popen(args, env=env)
    return True


def _update_dev(force: bool) -> int:
    sha = latest_commit()
    if sha and sha == installed_commit() and not force:
        print(f"Já está no commit mais recente do {BRANCH} ({sha[:7]}).")
        return 0
    if _continue_in_child(force, dev=True):
        return 0
    if os.environ.get(_CHILD_ENV):
        time.sleep(2)   # dá tempo do padme.exe que nos chamou terminar
    label = f"commit {sha[:7]} do {BRANCH}" if sha else f"branch {BRANCH}"
    rc = _install(archive_url(sha or BRANCH), label)
    if rc == 0:
        if sha:
            _save_state(sha=sha)
        print("Atualizado. Se o Padmé estiver rodando, reinicie-o para usar a versão nova.")
    return rc


def _update_release(force: bool) -> int:
    status, version = latest_release()
    if status == "nao_publicado":
        print("Ainda não há versão do Padmé publicada no PyPI.\n"
              "Para instalar o código mais recente do GitHub:  padme --update --dev")
        return 1
    if status != "ok" or version is None:
        print("Não consegui consultar o PyPI (sem rede?). Nada foi mudado.")
        return 1
    if version_key(version) <= version_key(__version__) and not force:
        print(f"Já está na versão mais recente ({__version__}).")
        return 0
    if _continue_in_child(force, dev=False):
        return 0
    if os.environ.get(_CHILD_ENV):
        time.sleep(2)
    rc = _install(f"{DIST}=={version}", f"versão {version} do PyPI")
    if rc == 0:
        _save_state(version=version)
        print(f"Atualizado para a versão {version}. Se o Padmé estiver rodando, "
              "reinicie-o para usar a versão nova.\nO que mudou: "
              f"https://github.com/{REPO}/blob/main/CHANGELOG.md")
    return rc


def run(force: bool = False, dev: bool = False) -> int:
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

    return _update_dev(force) if dev else _update_release(force)
