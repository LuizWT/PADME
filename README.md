# 🛰️ Padmé — Attack Surface Monitoring

> Vigia a superfície de ataque dos **seus** ativos ao longo do tempo e te avisa
> no **Telegram** sempre que algo muda: subdomínio novo, porta aberta,
> certificado trocado, serviço que subiu ou caiu — e **possível subdomain
> takeover**.

O AutoRecon faz uma foto. A **Padmé faz um filme** — ela guarda o estado e só
te chama quando a paisagem muda.

**Destaques**

- Monitoramento contínuo com **diff** entre varreduras (estado em SQLite).
- Alerta no **Telegram** com formatação estilo `git diff` e blocos recolhíveis.
- **Níveis de notificação** por severidade (`debug` → `critical`).
- **Detecção de subdomain takeover** (CNAME dangling + fingerprints).
- **Aviso de expiração de certificado TLS** (antes de virar incidente).
- **Export** do estado para JSON/CSV.
- Modo **sentinela** (`monitor`) que roda sozinho, 24/7.

---

## ⚖️ Uso responsável

Monitore **apenas** domínios/hosts que você é dono ou tem **autorização
explícita** para testar. A coleta ativa (HTTP, TLS e principalmente o scan de
portas) toca nos alvos. O `scope_confirmed: true` no config é uma trava
consciente — deixe-a como `true` só depois de confirmar seu escopo.

---

## 🧩 Como funciona

```
subdomains (CT logs)  ─┐
dns  A/AAAA/CNAME/MX   ─┤
http status/server     ─┤
tls  emissor/validade  ─┼─►  Records ─► diff vs. estado ─► eventos ─► nível ─► Telegram
takeover (CNAME+fp)    ─┤        (SQLite)
ports  connect-scan    ─┘
```

Cada fato observável vira um `Record (kind, key, value)`. O diff é uma
operação de conjuntos: `key` nova = **added**, `key` sumiu = **removed**,
mesmo `key` com `value` diferente = **changed**. Cada evento recebe uma
**severidade**, e o **nível** configurado decide o que chega no Telegram.

Fontes de subdomínio (passivas, Certificate Transparency):
`crt.name` e `crt.sh`. O parser é defensivo — extrai hostnames válidos sob o
apex independente do formato exato da resposta.

### 🎯 Subdomain takeover

Para cada host com **CNAME**, a Padmé casa o alvo contra uma base de serviços
(baseada no **can-i-take-over-xyz**: GitHub Pages, S3, Heroku, Azure, Shopify,
Fastly, Zendesk, etc.) e confirma de dois jeitos:

- **fingerprint** — busca o corpo HTTP e casa a assinatura de "recurso não
  reivindicado" (ex: *"There isn't a GitHub Pages site here."*);
- **nxdomain** — para serviços tipo Azure, se o alvo do CNAME não resolve, o
  apontamento está *dangling* → vulnerável.

Host sem CNAME nem entra na checagem (custo zero). Um achado vira um evento
`TAKEOVER`, que aparece no **topo** do alerta (severidade `critical`).

### ⏰ Expiração de certificado

O collector de TLS parseia o certificado (via `cryptography`, então funciona
até em cert self-signed ou já expirado) e, se ele estiver a **≤ N dias** de
expirar (`collectors.cert_expiry_days`, padrão 14), emite um evento
`CERT_EXPIRY` (severidade `high`). O valor gravado é estável (a data), então
você recebe **um** aviso ao entrar na janela — não um por dia. Se expirar de
vez, o evento vira `EXPIRADO`.

---

## 🚀 Instalação

```bash
git clone <seu-repo> padme && cd padme
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt         # ou: pip install -e .
cp config.example.yaml config.yaml      # e edite
```

## ⚙️ Configuração do Telegram

1. `@BotFather` → `/newbot` → copie o **bot token**.
2. Descubra seu **chat_id**: mande uma msg pro bot e abra
   `https://api.telegram.org/bot<TOKEN>/getUpdates` (campo `chat.id`),
   ou use `@userinfobot`.
3. Preencha `telegram.bot_token` e `telegram.chat_id` no `config.yaml`
   (ou use env vars: `bot_token: ${PADME_TG_TOKEN}`).

> **`.env`:** a Padmé carrega um `.env` na pasta do projeto automaticamente
> (via `python-dotenv`), então os `${PADME_TG_TOKEN}` / `${PADME_TG_CHAT}`
> resolvem no terminal, no cron e no systemd — sem depender do editor.

Teste:

```bash
python -m padme test-telegram
```

## 🕹️ Uso

```bash
# Scan único — grava/atualiza o baseline e imprime as mudanças
python -m padme scan

# Scan único que também dispara alerta no Telegram
python -m padme scan --notify

# Modo sentinela: varre em loop e alerta no Telegram (roda uma vez e esquece)
python -m padme monitor

# Sobrescrevendo intervalo e nível na hora
python -m padme monitor --interval 600 --level high

# Ver o histórico de eventos gravados
python -m padme events --limit 50

# Exportar o estado atual (JSON no stdout, ou CSV para um arquivo)
python -m padme export --format json
python -m padme export --format csv --out superficie.csv
```

> Se instalar com `pip install -e .`, o comando `padme` fica disponível
> direto (sem o `python -m`).

## 🔔 Níveis de notificação

O **terminal sempre mostra tudo**. O nível é o limiar mínimo de severidade que
é **enviado ao Telegram**:

| Nível | Envia |
|---|---|
| `critical` | só **takeover** |
| `high` | takeover + **porta/subdomínio novo** |
| `medium` *(padrão)* | acima + **HTTP/TLS mudou**, serviço novo |
| `low` | acima + remoções e mudanças menores |
| `debug` | **tudo**, inclusive registros DNS |

Defina em `config.yaml` (`telegram.level: high`) ou na hora
(`--level critical`). O `monitor` loga o nível ativo e, a cada ciclo, quantas
mudanças passaram no filtro.

## 📣 Canais de notificação

Os alertas (já filtrados pelo nível) vão para **todos** os canais habilitados:

- **Telegram** — formatação HTML estilo diff, com blocos recolhíveis.
- **Discord** — cole a URL de um *Webhook* de canal em `discord.webhook_url`
  (mensagem em Markdown).
- **Webhook genérico** — `webhook.url` recebe um **JSON estruturado** a cada
  mudança, ideal para **n8n** e automações:

  ```json
  {
    "source": "padme",
    "type": "changes",
    "target": "alvo.com",
    "time": "2026-09-24T00:46:00",
    "count": 2,
    "events": [
      {"severity": "critical", "kind": "takeover", "type": "added",
       "key": "blog.alvo.com", "old": null, "new": "GitHub Pages | ..."}
    ],
    "text": "**PADMÉ** · `alvo.com` ..."
  }
  ```

Todos aceitam `${VAR}` do `.env` (ex: `webhook_url: ${PADME_DISCORD_WEBHOOK}`).

## ⏱️ Rodando 24/7

- **systemd** (recomendado em servidor): crie um service que roda
  `python -m padme monitor` e reinicia sozinho.
- **cron + `scan --notify`**: se preferir não deixar processo vivo, agende
  `padme scan --notify` de hora em hora.
- **tmux/screen**: pro rápido e sujo.

---

## 🗺️ Roadmap (ideias)

- [x] Detecção de subdomain takeover (CNAME dangling + fingerprint)
- [x] Níveis de notificação por severidade
- [x] Notificadores extras: Discord + webhook genérico (JSON)
- [x] Aviso de expiração de certificado TLS
- [x] Export do estado para JSON/CSV
- [ ] Notificador de e-mail
- [ ] Wordlist de subdomínios (brute passivo → ativo opcional)
- [ ] Painelzinho web read-only do histórico

---

## 🧪 Testes

```bash
pip install pytest
pytest -q
```

## 📁 Estrutura

```
padme/
├── padme/
│   ├── cli.py            # comandos scan / monitor / events / test-telegram
│   ├── config.py         # carrega e valida o YAML
│   ├── models.py         # Record / Event / Kind
│   ├── levels.py         # severidade dos eventos + filtro por nível
│   ├── storage.py        # SQLite: estado + histórico
│   ├── differ.py         # engine de diff (puro, testável)
│   ├── engine.py         # orquestra collectors + diff
│   ├── scheduler.py      # loop do modo sentinela (monitor)
│   ├── collectors/       # subdomains, dns, http, tls, takeover, ports
│   └── notify/           # telegram, discord, webhook genérico (JSON)
├── config.example.yaml
├── requirements.txt
├── pyproject.toml
└── tests/                # differ, takeover, levels, notify, certexpiry, export
```
