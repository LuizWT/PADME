"""Ponto de entrada (`padme` e `python -m padme`).

Leve de propósito: `--update` é tratado ANTES de importar a CLI (e com ela os
collectors e as dependências com extensões compiladas). No Windows, arquivo
de extensão carregado fica travado e o pip não conseguiria atualizá-lo.
"""

import sys


def run(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    if "--update" in args:
        from .updater import run as update
        return update(force="--force" in args)
    from .cli import main
    return main(args)


if __name__ == "__main__":
    raise SystemExit(run())
