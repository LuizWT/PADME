# Runbook operacional — Padmé

Operação real do sentinela: rodar 24/7, backup, rotação de segredos, exposição
do painel e manutenção. Tudo alinhado ao funcionamento atual (`padme monitor`,
SQLite em WAL, `.env`, variáveis `PADME_*`, lock de instância única).

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
sudo /opt/padme/.venv/bin/pip install /caminho/do/repo   # ou: pip install "git+https://github.com/LuizWT/PADME.git"
sudo cp config.example.yaml /var/lib/padme/config.yaml    # e edite (scope_confirmed: true, targets)
sudo chown -R padme:padme /var/lib/padme
sudo chmod 750 /var/lib/padme
```

Segredos ficam em `/var/lib/padme/.env` (nunca versionado), lido sozinho pela
CLI. Permissão restrita:

```bash
sudo tee /var/lib/padme/.env >/dev/null <<'EOF'
PADME_TG_TOKEN=...
PADME_TG_CHAT=...
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

### Variante cron-like (sem processo vivo)

Se preferir um ciclo por vez em vez de processo residente, use um `.timer` com
`monitor --once --lock` (o lock evita sobreposição se um ciclo demora):

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

---

## 2. Backup do SQLite

O banco fica em **WAL**, então **não** copie o `.db` com `cp` durante a escrita
(pode pegar um snapshot inconsistente, sem o que ainda está no `-wal`). Use a API
de backup online do SQLite, que é consistente mesmo com o monitor rodando:

```bash
sqlite3 /var/lib/padme/padme.db ".backup '/var/backups/padme/padme-$(date +%F_%H%M).db'"
```

**Validação** (todo backup deveria ser testado):

```bash
sqlite3 /var/backups/padme/padme-2026-09-27_0300.db "PRAGMA integrity_check;"   # espera 'ok'
```

**Agendamento** (cron do usuário `padme`, 03:00, retenção de 14 dias):

```cron
0 3 * * *  sqlite3 /var/lib/padme/padme.db ".backup '/var/backups/padme/padme-$(date +\%F).db'" && find /var/backups/padme -name 'padme-*.db' -mtime +14 -delete
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

## 3. Rotação de segredos

Todos os segredos vivem no `.env` (`PADME_*`) — nada no `config.yaml` versionado.
Para trocar qualquer um:

1. Gere o novo segredo no provedor (BotFather, Discord, SMTP, etc.).
2. Edite `/var/lib/padme/.env` com o valor novo.
3. Reinicie o serviço: `sudo systemctl restart padme` (o `.env` é relido no start).
4. Valide: `padme -c /var/lib/padme/config.yaml test-notify` (testa todos os canais).
5. **Revogue o antigo** no provedor (senão ele continua válido).

| segredo | variável | onde trocar | como revogar o antigo |
|---|---|---|---|
| Telegram bot | `PADME_TG_TOKEN` | @BotFather → `/revoke` gera novo | o `/revoke` já invalida o anterior |
| Discord webhook | `PADME_DISCORD_WEBHOOK` | Config. do canal → Integrações | apague o webhook antigo |
| Webhook (n8n/próprio) | `PADME_WEBHOOK_URL` / `PADME_WEBHOOK_TOKEN` | seu endpoint | rejeite o token antigo no endpoint |
| SMTP | `PADME_SMTP_USER` / `PADME_SMTP_PASS` | provedor (Gmail: App Password) | remova a App Password antiga |
| Painel web | `PADME_WEB_TOKEN` | gere um novo (`openssl rand -hex 32`) | reinicie o `padme web` |
| Heartbeat | `PADME_HEARTBEAT_URL` | watchdog (healthchecks.io…) | apague o check antigo |

> O log nunca imprime segredos (httpx silenciado + filtro de redação, mesmo com
> `-v`). Ainda assim, evite `echo`/`cat` do `.env` em terminais compartilhados.

---

## 4. Painel web atrás de proxy (TLS)

O `padme web` **não** faz TLS e, por padrão, escuta só em `127.0.0.1`. Expor
`0.0.0.0:8787` direto na internet entrega sua superfície de ataque a qualquer um
— por isso o Padmé **recusa** servir fora de localhost sem token (a menos de
`--allow-no-auth`, decisão consciente). O caminho correto é:

**Padmé em loopback + token → proxy reverso termina o TLS → repassa o header.**

```bash
export PADME_WEB_TOKEN="$(openssl rand -hex 32)"
padme -c /var/lib/padme/config.yaml web        # 127.0.0.1:8787, exige Bearer
```

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

Assim: o Padmé nunca fica exposto direto, o TLS é do proxy, e o `Bearer` do
Padmé segue exigido ponta a ponta. (Você pode deixar o proxy adicionar o header
para os clientes, ou exigir que cada cliente mande o seu.)

---

## 5. Manutenção do banco

- **Diagnóstico:** `padme -c .../config.yaml doctor` mostra integridade
  (`PRAGMA integrity_check`), contagens, **tamanho do banco (db + WAL)** e a
  saúde da última coleta por alvo.
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
  (seção 2) — não tente reparar o arquivo em produção.
