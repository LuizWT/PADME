# Padmé — imagem para rodar o sentinela 24/7.
#
#   docker build -t padme .
#   docker run --rm  -v "$PWD/data:/data" --user "$(id -u):$(id -g)" padme test-notify
#   docker run -d --name padme --restart unless-stopped \
#       -v "$PWD/data:/data" --user "$(id -u):$(id -g)" padme monitor
#
# Espera a config em /data/config.yaml e grava o estado em /data/padme.db,
# então monte um volume em /data (o .env em /data também é lido sozinho).
# Base fixada por DIGEST (build reproduzível: a tag 3.12-slim anda sozinha).
# O Dependabot (ecossistema docker) abre PR quando a tag ganha digest novo.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

# stdout sem buffer (log aparece na hora) e sem .pyc no container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Dependências nas versões FIXAS do lock (build reproduzível), depois o pacote
# sem resolver dependências de novo (o entrypoint `padme` vem do pyproject).
COPY pyproject.toml requirements.txt README.md ./
COPY padme ./padme
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps . \
    && useradd --system --uid 1000 --create-home --home-dir /data padme

# /data guarda config.yaml, .env e padme.db — monte um volume aqui.
WORKDIR /data
USER padme
VOLUME ["/data"]

# Liveness pelo banco (sem rede): unhealthy se o último scan passou de
# 2*interval_seconds + 10min. start-period cobre a baseline do primeiro ciclo.
HEALTHCHECK --interval=5m --timeout=30s --start-period=30m --retries=3 \
    CMD ["padme", "-c", "/data/config.yaml", "health"]

# `padme -c /data/config.yaml <comando>`; padrão: modo sentinela.
ENTRYPOINT ["padme", "-c", "/data/config.yaml"]
CMD ["monitor"]
