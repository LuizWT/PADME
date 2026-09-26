#!/usr/bin/env sh
# Empacota um release LIMPO usando git archive: só entra o que está versionado,
# então .env, config.yaml, *.db e runtime state NUNCA vão no pacote (mesmo que
# existam no diretório de trabalho). Nada de "zipar a pasta na mão".
set -eu
ref="${1:-HEAD}"
ver="$(git describe --tags --always 2>/dev/null || echo dev)"
out="padme-${ver}.tar.gz"
git archive --format=tar.gz --prefix="padme-${ver}/" -o "$out" "$ref"
echo "release gerado: $out"
echo "conteúdo (deve NÃO conter .env/config.yaml/*.db):"
tar tzf "$out" | sed 's/^/  /'
