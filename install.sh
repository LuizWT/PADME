#!/bin/sh
# Instalador do Padmé para Linux e macOS.
#
#   sh install.sh                 # dentro da pasta baixada/clonada
#   curl -fsSL https://raw.githubusercontent.com/LuizWT/PADME/main/install.sh | sh
#   sh install.sh --uninstall     # remove o programa (mantém config e banco)
#
# O que faz: acha um Python 3.10+, cria um ambiente isolado em
# ~/.local/share/padme, instala o Padmé nele, cria o comando `padme` em
# ~/.local/bin (e põe essa pasta no PATH) e, se ainda não houver config, roda
# o `padme init`. Não usa sudo e não mexe no Python do sistema.
set -eu

REPO="LuizWT/PADME"
REF="${PADME_REF:-main}"
APP_HOME="${PADME_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/padme}"
BIN_DIR="${PADME_BIN:-$HOME/.local/bin}"
VENV="$APP_HOME/venv"
LAUNCHER="$BIN_DIR/padme"
MARK="# padme: comando no PATH"

say() { printf '%s\n' "$*"; }
fail() { printf '\nERRO: %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    rm -rf "$VENV" "$LAUNCHER"
    rm -f "$APP_HOME/update.json"
    rmdir "$APP_HOME" 2>/dev/null || true
    say "Padmé removido. Config e banco continuam em ${XDG_CONFIG_HOME:-$HOME/.config}/padme"
    say "(apague essa pasta se não quiser mais os dados)."
    exit 0
fi

say "== Instalando o Padmé =="

# 1) Python 3.10 ou mais novo
PY=""
for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$c" >/dev/null 2>&1 &&
        "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$c"
        break
    fi
done
if [ -z "$PY" ]; then
    say "Não achei o Python 3.10 ou mais novo. Instale e rode este instalador de novo:"
    say "  Debian/Ubuntu:  sudo apt install python3 python3-venv"
    say "  Fedora:         sudo dnf install python3"
    say "  Arch:           sudo pacman -S python"
    say "  macOS:          brew install python   (ou o instalador de python.org)"
    exit 1
fi
if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
    fail "falta o módulo venv do Python. No Debian/Ubuntu: sudo apt install python3-venv"
fi
say "Python: $("$PY" -c 'import sys; print(sys.version.split()[0])') ($PY)"

# 2) de onde instalar: a pasta deste script (clone ou zip baixado) ou o GitHub
SRC="https://github.com/$REPO/archive/$REF.zip"
HERE=""
if [ -f "$0" ]; then   # rodando de um arquivo (não via "curl | sh")
    HERE=$(cd "$(dirname "$0")" && pwd)
fi
if [ -n "$HERE" ] && [ -f "$HERE/pyproject.toml" ] && grep -q 'padme-asm' "$HERE/pyproject.toml"; then
    SRC="$HERE"
fi
SRC="${PADME_SRC:-$SRC}"
say "Origem: $SRC"

# 3) ambiente isolado e instalação
mkdir -p "$APP_HOME"
if [ ! -x "$VENV/bin/python" ]; then
    "$PY" -m venv "$VENV" || fail "não consegui criar o ambiente em $VENV"
fi
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade pip
"$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade "$SRC" ||
    fail "a instalação pelo pip falhou (veja a mensagem acima)."

# 4) comando `padme` (chama o Python do ambiente: nada de "python padme")
mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<EOF
#!/bin/sh
exec "$VENV/bin/python" -m padme "\$@"
EOF
chmod +x "$LAUNCHER"

# 5) ~/.local/bin no PATH (shells novos); a sessão atual usa o caminho completo
NEW_SHELL=0
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
            if [ -f "$rc" ] || [ "$rc" = "$HOME/.profile" ]; then
                if ! grep -qF "$MARK" "$rc" 2>/dev/null; then
                    # $PATH literal de propósito: expande quando o terminal abrir
                    # shellcheck disable=SC2016
                    printf '\n%s\nexport PATH="%s:$PATH"\n' "$MARK" "$BIN_DIR" >> "$rc"
                fi
            fi
        done
        NEW_SHELL=1
        ;;
esac

say "Instalado: $("$LAUNCHER" --version)"

# 6) config: se ainda não existe, cria agora (lendo do terminal mesmo via curl | sh)
CONFIG=$("$VENV/bin/python" -c 'from padme.paths import find_config; print(find_config())')
if [ -f "$CONFIG" ]; then
    say "Config existente mantido: $CONFIG"
elif (: < /dev/tty) 2>/dev/null; then
    say ""
    "$LAUNCHER" init < /dev/tty || say "Rode depois: padme init"
else
    say "Sem terminal para perguntar. Crie o config depois com: padme init"
fi

say ""
say "== Pronto =="
if [ "$NEW_SHELL" = 1 ]; then
    say "Abra um terminal NOVO (ou rode: export PATH=\"$BIN_DIR:\$PATH\") e digite:"
else
    say "Digite:"
fi
say "  padme              monitora e abre o painel em http://127.0.0.1:8787"
say "  padme -h           todas as opções"
say "  padme --update     atualiza para a versão mais recente"
