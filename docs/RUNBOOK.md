# Runbook operacional — Padmé

[Voltar ao README](../README.md)

Para rodar num servidor 24/7: systemd, Docker, backup, rotação de segredos,
painel atrás de proxy com TLS e manutenção. Num computador pessoal, o
instalador e o comando `padme` bastam; este guia é para servidor.

- [1. systemd](#1-systemd-sentinela-247)
- [2. Docker](#2-docker)
- [3. Backup do SQLite](#3-backup-do-sqlite)
- [4. Rotação de segredos](#4-rotação-de-segredos)
- [5. Painel atrás de proxy (TLS)](#5-painel-web-atrás-de-proxy-tls)
- [6. Manutenção do banco](#6-manutenção-do-banco)
- [7. Manutenção periódica](#7-manutenção-periódica-dependências-e-base-de-detecção)

Convenção usada aqui (ajuste aos seus caminhos):

| item              | caminho                         |
|-------------------|---------------------------------|
| venv / instalação | `/opt/padme/.venv`              |
| dados (db, config, .env) | `/var/lib/padme`         |
| usuário de serviço | `padme` (sem shell, sem login) |

```bash
sudo useradd --system --home-dir /var/lib/padme --shell /usr/sbin/nologin padme
sudo mkdir -p /opt/padme /var/lib/padme
sudo python3 -m venv /opt/padme/.venv
sudo /opt/padme/.venv/bin/pip install "https://github.com/LuizWT/PADME/archive/main.zip"
sudo /opt/padme/.venv/bin/padme -c /var/lib/padme/config.yaml init   # ou copie e edite o config.example.yaml
sudo chown -R padme:padme /var/lib/padme
sudo chmod 750 /var/lib/padme
```

Segredos ficam em `/var/lib/padme/.env` (nunca versionado), lido sozinho pela
CLI. Permissão restrita:

```bash
sudo tee /var/lib/padme/.env >/dev/null <<'EOF'
PADME_TELEGRAM_TOKEN=...
PADME_DISCORD_WEBHOOK=...
PADME_WEBHOOK_URL=...
PADME_WEBHOOK_TOKEN=...
PADME_SMTP_USER=...
PADME_SMTP_PASS=...
PADME_HEARTBEAT_URL=...
PADME_WEB_TOKEN=...
EOF
sudo chown padme:padme /var/lib/padme/.env
sudo chmod 600 /var/lib/padme/.env
```

---

## 1. systemd (sentinela 24/7)

`/etc/systemd/system/padme.service` — processo vivo, reinício automático,
hardening compatível com o que o Padmé realmente faz (rede + escrita só no
diretório de dados):

```ini
[Unit]
Description=Padmé — Attack Surface Monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=padme
Group=padme
WorkingDirectory=/var/lib/padme
EnvironmentFile=/var/lib/padme/.env
# o monitor já serve o painel em 127.0.0.1:8787; --no-web se não quiser
ExecStart=/opt/padme/.venv/bin/padme -c /var/lib/padme/config.yaml monitor
Restart=always
RestartSec=10

# --- hardening (só o que NÃO quebra o Padmé) ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict          # todo o FS read-only...
ReadWritePaths=/var/lib/padme  # ...menos o diretório de dados (db em WAL)
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6   # precisa de rede; sem AF_UNIX extra
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now padme.service
journalctl -u padme -f            # logs (sem segredos — são mascarados)
```

> `ProtectSystem=strict` + `ReadWritePaths=/var/lib/padme` é o par importante: o
> SQLite em WAL escreve `padme.db`, `padme.db-wal` e `padme.db-shm` — todos no
> diretório de dados, que é o único gravável.

> `systemctl stop` manda SIGTERM: o monitor trata como Ctrl+C (avisa
> "monitoramento encerrado" nos canais e fecha o banco). Para checar liveness de
> fora (cron, Nagios, uptime-kuma), `padme -c /var/lib/padme/config.yaml health`
> sai com 1 se o último scan passou de `2*interval_seconds + 10min`.

### Variante cron-like (sem processo vivo)

Se preferir um ciclo por vez em vez de processo residente, use um `.timer` com
`monitor --once --lock` (o lock evita sobreposição se um ciclo demora; o
`--once` não abre painel):

`/etc/systemd/system/padme.service` (Type=oneshot):

```ini
[Service]
Type=oneshot
User=padme
EnvironmentFile=/var/lib/padme/.env
WorkingDirectory=/var/lib/padme
ExecStart=/opt/padme/.venv/bin/padme -c /var/lib/padme/config.yaml monitor --once --lock /var/lib/padme/padme.lock
```

`/etc/systemd/system/padme.timer`:

```ini
[Unit]
Description=Roda o Padmé periodicamente
[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now padme.timer
```

Com cron puro, o equivalente é:

```cron
0 * * * *  /opt/padme/.venv/bin/padme -c /var/lib/padme/config.yaml monitor --once --lock /var/lib/padme/padme.lock
```

---

## 2. Docker

A config, o `.env` e o banco ficam numa pasta montada em `/data`.

```bash
mkdir -p data
cp config.example.yaml data/config.yaml     # edite: scope_confirmed, targets, canais
docker compose up -d                        # restart automático já configurado
docker compose logs -f
```

Sem compose:

```bash
docker build -t padme .
docker run -d --name padme --restart unless-stopped \
    -v "$PWD/data:/data" --user "$(id -u):$(id -g)" padme
```

- Outros comandos usam a mesma imagem: `docker compose run --rm padme finding list`.
- `--user "$(id -u):$(id -g)"` faz o `padme.db` ficar com o seu usuário. No
  compose, ajuste `user:` se o seu `id -u`/`id -g` não for `1000`.
- A imagem tem `HEALTHCHECK` (`padme health`): o container fica `unhealthy` se a
  última varredura passou de `2*interval_seconds + 10min`.
- `docker stop` encerra limpo: avisa "monitoramento encerrado" nos canais e
  fecha o banco.
- Atualizar: `git pull && docker compose build --pull && docker compose up -d`
  (o `padme --update` não se aplica à imagem).

**Painel no navegador do host.** Dentro do container, o painel precisa escutar
em todas as interfaces, e isso exige token. Em `data/config.yaml`:

```yaml
web:
  bind: 0.0.0.0
  token: ${PADME_WEB_TOKEN}
```

Defina `PADME_WEB_TOKEN` em `data/.env` e descomente `ports:` no
`docker-compose.yml`. Sem token, o monitor roda normalmente, só sem painel.

---

## 3. Backup do SQLite

O banco fica em **WAL**, então **não** copie o `.db` com `cp` durante a escrita
(pode pegar um snapshot inconsistente, sem o que ainda está no `-wal`). Use o
backup online — consistente mesmo com o monitor rodando. A Padmé traz um comando
que faz isso (API de backup do SQLite) e já valida a integridade do destino:

```bash
padme -c /etc/padme/config.yaml backup --out /var/backups/padme/padme-$(date +%F_%H%M).db
# imprime destino, tamanho e integridade (sai != 0 se a integridade não for 'ok')
```

Equivalente só com o `sqlite3` (sem a Padmé instalada):

```bash
sqlite3 /var/lib/padme/padme.db ".backup '/var/backups/padme/padme-$(date +%F_%H%M).db'"
```

**Validação** (todo backup deveria ser testado) — o `padme backup` já roda o
`integrity_check`; para conferir um arquivo à parte:

```bash
sqlite3 /var/backups/padme/padme-2026-09-27_0300.db "PRAGMA integrity_check;"   # espera 'ok'
```

**Agendamento** (cron do usuário `padme`, 03:00, retenção de 14 dias):

```cron
0 3 * * *  padme -c /etc/padme/config.yaml backup --out "/var/backups/padme/padme-$(date +\%F).db" && find /var/backups/padme -name 'padme-*.db' -mtime +14 -delete
```

- Guarde os backups **fora** do host (rsync/objeto remoto) — um backup no mesmo
  disco não te salva de perder o disco.
- Permissões: `chmod 600` e dono `padme` (o backup contém toda a sua superfície).

**Restauração:**

```bash
sudo systemctl stop padme            # nada escrevendo
sudo -u padme cp /var/backups/padme/padme-<data>.db /var/lib/padme/padme.db
sudo -u padme rm -f /var/lib/padme/padme.db-wal /var/lib/padme/padme.db-shm
sudo systemctl start padme
padme -c /var/lib/padme/config.yaml doctor   # confirma integridade
```

---

## 4. Rotação de segredos

Todos os segredos vivem no `.env` (`PADME_*`) — nada no `config.yaml` versionado.
Para trocar qualquer um:

1. Gere o novo segredo no provedor (BotFather, Discord, SMTP, etc.).
2. Edite `/var/lib/padme/.env` com o valor novo.
3. Reinicie o serviço: `sudo systemctl restart padme` (o `.env` é relido no start).
4. Valide: `padme -c /var/lib/padme/config.yaml digest` manda o resumo agora e
   mostra `OK` ou `ERRO` por canal.
5. **Revogue o antigo** no provedor (senão ele continua válido).

| segredo | variável | onde trocar | como revogar o antigo |
|---|---|---|---|
| Telegram bot | `PADME_TELEGRAM_TOKEN` | @BotFather → `/revoke` gera novo | o `/revoke` já invalida o anterior |
| Discord webhook | `PADME_DISCORD_WEBHOOK` | Config. do canal → Integrações | apague o webhook antigo |
| Webhook (n8n/próprio) | `PADME_WEBHOOK_URL` / `PADME_WEBHOOK_TOKEN` | seu endpoint | rejeite o token antigo no endpoint |
| SMTP | `PADME_SMTP_USER` / `PADME_SMTP_PASS` | provedor (Gmail: App Password) | remova a App Password antiga |
| Painel web | `PADME_WEB_TOKEN` | gere um novo (`openssl rand -hex 32`) | reinicie o serviço |
| Heartbeat | `PADME_HEARTBEAT_URL` | watchdog (healthchecks.io…) | apague o check antigo |

> O log nunca imprime segredos (httpx silenciado + filtro de redação, mesmo com
> `-v`). Ainda assim, evite `echo`/`cat` do `.env` em terminais compartilhados.

---

## 5. Painel web atrás de proxy (TLS)

O painel (que sobe junto com o `padme monitor`, ou sozinho com `padme web`)
**não** faz TLS e, por padrão, escuta só em `127.0.0.1`. Expor `0.0.0.0:8787`
direto na internet entrega sua superfície de ataque a qualquer um; por isso o
Padmé **recusa** servir fora de localhost sem token (a menos de
`--allow-no-auth`). O caminho correto é:

**Padmé em loopback + token → proxy reverso termina o TLS → repassa o header.**

Coloque `PADME_WEB_TOKEN` no `.env` (gere com `openssl rand -hex 32`) e
reinicie o serviço: o painel continua em `127.0.0.1:8787`, agora exigindo o token.

O TLS termina no proxy; o token do Padmé continua valendo porque o proxy
**repassa** o `Authorization`. nginx:

```nginx
server {
    listen 443 ssl;
    server_name painel.seu-dominio.com;
    ssl_certificate     /etc/letsencrypt/live/painel.seu-dominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/painel.seu-dominio.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;   # repassa o Bearer
    }
    location /live {                     # atualização em tempo real (SSE)
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Authorization $http_authorization;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

Caddy (TLS automático):

```
painel.seu-dominio.com {
    reverse_proxy 127.0.0.1:8787 {
        header_up Authorization {http.request.header.Authorization}
    }
}
```

Assim: o Padmé nunca fica exposto direto, o TLS é do proxy, e o token do
Padmé segue exigido ponta a ponta. No navegador, o próprio Padmé pede login
(HTTP Basic: qualquer usuário, o token como senha) — o `proxy_set_header
Authorization` acima repassa isso sem mudança. Em automação, use `Bearer`.

A **API** (`padme api`, read-only, `/api/v1`) segue o mesmo modelo: loopback por
padrão, exige `Bearer` fora de localhost e vai atrás do mesmo proxy — só numa
porta própria (padrão `8788`; ajuste o `proxy_pass`/`reverse_proxy`). O token é o
`PADME_API_TOKEN`, ou o do painel se aquele estiver vazio. Como é só Bearer (sem
o prompt Basic do navegador), é o alvo natural para SIEM/ticketing/cron.

---

## 6. Manutenção do banco

- **Diagnóstico:** `padme -c .../config.yaml doctor` mostra integridade
  (`PRAGMA integrity_check`), contagens, **tamanho do banco (db + WAL)**, a
  saúde da última coleta por alvo e **sondas de rede** (TCP/53 e HTTPS de
  saída). Se o doctor marca TCP/53 bloqueado, o SPF de domínios com muitos
  includes fica inconclusivo até liberar a porta no firewall.
- **Retenção:** o `state` (foto atual) nunca é apagado. Os **eventos** crescem em
  24/7 — defina `storage.event_retention_days` (0 = mantém tudo) e o monitor poda
  a cada ciclo.
- **Compactação:** depois de podar muito histórico, o arquivo não encolhe
  sozinho. Com o serviço parado:

  ```bash
  sudo systemctl stop padme
  sudo -u padme sqlite3 /var/lib/padme/padme.db "VACUUM;"
  sudo systemctl start padme
  ```

- **Corrupção:** se o `doctor` não retornar `ok`, restaure o último backup bom
  (seção 3) — não tente reparar o arquivo em produção.

---

## 7. Manutenção periódica (dependências e base de detecção)

- **PRs do Dependabot (semanal):** lock Python (`requirements*.txt`), GitHub
  Actions e digest da imagem `python:3.12-slim`. Só faça merge com o CI verde —
  ele roda a suíte, o `pip-audit` e o build + smoke test da imagem. O
  `publicsuffixlist` sai com versão nova a cada atualização da Public Suffix
  List; entra no mesmo grupo semanal.
- **Auditoria semanal:** o workflow roda sozinho toda segunda (cron). Se o job
  `audit` ficar vermelho sem ninguém ter mexido no código, é CVE nova numa
  dependência: atualize a versão no lock (ou aceite o PR do Dependabot).
- **Base de takeover:** quando o `padme doctor` avisar que passou de 180 dias,

  ```bash
  python scripts/update_takeover_fingerprints.py --check   # revise o diff
  python scripts/update_takeover_fingerprints.py           # grava + marca revisão
  pytest -q tests/test_takeover_base.py
  ```

  Serviço que o upstream rebaixar para "Not vulnerable" sai da base (menos
  falso positivo); serviço novo sem alvo de CNAME no upstream é listado como
  "(fora)" — só entra se você souber o domínio da plataforma (edite `_CURATED`
  no script). O `--check` sai com 3 quando os serviços mudam e 0 quando só a
  data mudaria.

- **Base de takeover (automático):** o workflow **takeover base** roda o script
  todo dia 1 e abre um PR só quando os serviços do upstream mudam. Na prática
  você revisa o diff e dá merge, em vez de lembrar de rodar o script — mas o
  comando manual acima continua valendo quando quiser forçar.
