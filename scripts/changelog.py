"""Imprime a seção de uma versão do CHANGELOG.md (as notas da release).

    python scripts/changelog.py v0.2.0          # ou 0.2.0
    python scripts/changelog.py 0.2.0 outro.md

Sai com 1 se a versão não tiver seção ou se a seção estiver vazia: o workflow
de release usa isso para não publicar uma versão sem notas.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def section(text: str, version: str) -> str | None:
    """Corpo da seção `## [versão]`, até a próxima seção ou os links do fim."""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|^\[[^\]]+\]: |\Z)",
                  text, re.M | re.S)
    if not m:
        return None
    body = m.group(1).strip()
    return body or None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    path = Path(argv[2]) if len(argv) > 2 else Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    body = section(path.read_text(encoding="utf-8"), version)
    if body is None:
        print(f"{path.name} não tem a seção [{version}] (ou ela está vazia).", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
