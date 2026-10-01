#!/bin/sh
# Smoke test da imagem: prova o que só aparece num container de verdade
# (entrypoint, usuário, HEALTHCHECK, dados empacotados, SIGTERM como PID 1).
# Não sonda nada na rede: o alvo é .invalid e os collectors ficam desligados.
#
#   docker build -t padme:ci . && sh scripts/docker-smoke.sh padme:ci
set -eu

IMG="${1:-padme:ci}"
NAME="padme-smoke-$$"
DATA="$(mktemp -d)"
chmod 777 "$DATA"   # o container grava como uid 1000
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$DATA"' EXIT

run() { docker run --rm -v "$DATA:/data" "$@"; }

echo "1) entrypoint e versão"
docker run --rm "$IMG" --version

echo "2) HEALTHCHECK declarado na imagem"
docker inspect --format '{{json .Config.Healthcheck.Test}}' "$IMG" | grep -q '"health"'

echo "3) roda sem privilégio"
[ "$(docker run --rm --entrypoint id "$IMG" -u)" != "0" ]

echo "4) dados do pacote presentes (base de takeover + Public Suffix List offline)"
docker run --rm --network none --entrypoint python "$IMG" -c \
    "from padme.collectors.takeover import FINGERPRINTS; \
from padme.domains import registrable_domain as r; \
assert FINGERPRINTS and r('a.b.co.uk') == 'b.co.uk' and r('x.local') is None"

cat > "$DATA/config.yaml" <<'YAML'
scope_confirmed: true
interval_seconds: 3600
targets:
  - smoke.invalid
collectors:
  subdomains: false
  wildcard: false
  dns: false
  dns_records: false
  http: false
  favicon: false
  tls: false
  takeover: false
  ports: false
YAML

echo "5) health sem banco -> unhealthy (exit 1)"
if run "$IMG" health; then
    echo "esperava exit 1 sem banco" >&2
    exit 1
fi

echo "6) docker stop (SIGTERM no PID 1) encerra limpo, sem esperar o SIGKILL"
docker run -d --name "$NAME" -v "$DATA:/data" "$IMG" monitor >/dev/null
i=0
until docker logs "$NAME" 2>&1 | grep -q "Ciclo #1"; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then docker logs "$NAME"; exit 1; fi
    sleep 1
done
docker stop -t 20 "$NAME" >/dev/null
code="$(docker inspect -f '{{.State.ExitCode}}' "$NAME")"
if [ "$code" != "0" ]; then
    echo "exit $code (137 = SIGTERM ignorado, morreu no SIGKILL)" >&2
    docker logs "$NAME"
    exit 1
fi
docker logs "$NAME" 2>&1 | grep -q "Encerrando sentinela"

echo "7) health depois de um ciclo -> healthy (exit 0)"
run "$IMG" health

echo "smoke OK"
