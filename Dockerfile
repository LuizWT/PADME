# Padmé — imagem para rodar o sentinela 24/7.
#
#   docker build -t padme .
#   docker run --rm  -v "$PWD/data:/data" --user "$(id -u):$(id -g)" padme test-notify
#   docker run -d --name padme --restart unless-stopped \
#       -v "$PWD/data:/data" --user "$(id -u):$(id -g)" padme monitor
#
# Espera a config em /data/config.yaml e grava o estado em /data/padme.db,
# então monte um volume em /data (o .env em /data também é lido sozinho).
FROM python:3.12-slim

# stdout sem buffer (log aparece na hora) e sem .pyc no container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Instala o pacote (o pyproject já traz as dependências e o entrypoint `padme`).
COPY pyproject.toml requirements.txt README.md ./
COPY padme ./padme
RUN pip install --no-cache-dir . \
    && useradd --system --uid 1000 --create-home --home-dir /data padme

# /data guarda config.yaml, .env e padme.db — monte um volume aqui.
WORKDIR /data
USER padme
VOLUME ["/data"]

# `padme -c /data/config.yaml <comando>`; padrão: modo sentinela.
ENTRYPOINT ["padme", "-c", "/data/config.yaml"]
CMD ["monitor"]
