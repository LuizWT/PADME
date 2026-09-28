# Padmé — Attack Surface Monitoring

![tests](https://github.com/LuizWT/PADME/actions/workflows/tests.yml/badge.svg)

> Vigia a superfície de ataque dos **seus** ativos ao longo do tempo e te avisa
> no **Telegram, Discord, E-mail e/ou outro** sempre que algo muda: subdomínio novo, porta aberta,
> certificado trocado, serviço que subiu ou caiu — e **possível subdomain
> takeover**.

**A Padmé faz um filme:** guardando o estado e só
te chama quando a paisagem muda.

**Destaques**

- Monitoramento contínuo com **diff** entre varreduras (estado em SQLite).
- Alerta no **Telegram** com formatação estilo `git diff` e blocos recolhíveis.
- Canais: **Telegram**, **Discord**, **webhook JSON** e **e-mail** (SMTP), cada um
  com o **seu próprio nível** de severidade (política por canal).
- **Confiabilidade primeiro:** erro de coleta (timeout, fonte fora do ar) **não**
  vira "recurso removido" — o estado é preservado; o 1º scan é **baseline** (não
  polui o histórico); notificações têm **retry** e um canal não derruba os outros.
- **Segurança operacional:** segredos nunca aparecem nos logs; sem seguir
  redirects e sem sondar IP privado/reservado por padrão (anti-SSRF/rede interna).
- **`padme doctor`** (integridade do banco + saúde dos scans) e **retenção** de
  histórico configurável.
- **Detecção de subdomain takeover** (CNAME dangling + fingerprints).
- **Sinais RED**: mudança de **NS** (delegação / hijack de zona), **SPF/DMARC**
  (remoção = domínio spoofável) e **banner-grab** nas portas (mudança de banner
  = versão de serviço mudou).
- **Multi-vantage**: cada instância é um `source`; `padme merge` consolida os
  exports e mostra **divergências** entre pontos de observação (geo-block,
  split-horizon, host que só aparece de um lugar).
- **Metadata estruturada** por evento (issuer/expira/fingerprint/SANs, status/server,
  service/reason…) no webhook — n8n consome campos, não parseia string.
- **Amortecimento de flapping**: chave que oscila para de spammar (segue no
  histórico). **Validação forte de config** (falha cedo com mensagem clara).
- **Aviso de expiração de certificado TLS** (antes de virar incidente).
- **Bruteforce de subdomínios** por wordlist (opcional) + CT logs.
- **Qualidade de sinal**: subdomínio `live`/`quiet` + **detecção de wildcard DNS**
  (suprime a inundação de falso-positivo do bruteforce em apex catch-all).
- **Export** para JSON/CSV e **painel web** read-only, com **gráfico de
  tendência** (eventos/dia nos últimos 30d) — enxerga a superfície crescer/encolher.
- Modo **sentinela** (`monitor`) que roda sozinho, 24/7, com **heartbeat /
  dead-man's switch** (avisa que está vivo; silêncio = watchdog externo alerta).
- `--once` + `--lock` (flock) para rodar via **cron** sem execuções sobrepostas.

---

## Uso responsável

> [!WARNING]
> Monitore **apenas** domínios/hosts que você é dono ou tem **autorização
> explícita** para testar. A coleta ativa (HTTP, TLS e principalmente o scan de
> portas) toca nos alvos.

> [!IMPORTANT]
> O `scope_confirmed: true` no config é uma trava consciente — deixe-a como
> `true` só depois de confirmar seu escopo. Sem ela, os comandos que varrem
> alvos se recusam a rodar.

---

## Como funciona?

```
subdomains (CT logs)  ─┐                                          ┌─► Telegram (nível próprio)
dns  A/AAAA/CNAME/MX   ─┤                                          ├─► Discord  (nível próprio)
http status/server     ─┼─► Records + escopos observados ─► diff ─┤
tls  emissor/validade  ─┤        vs. estado (SQLite)     ─► eventos├─► Webhook  (nível próprio)
takeover (CNAME+fp)    ─┤                                          └─► E-mail   (nível próprio)
ports  connect-scan    ─┘
```

Cada fato observável vira um `Record (kind, key, value)`. O diff é uma
operação de conjuntos: `key` nova = **added**, `key` sumiu = **removed**,
mesmo `key` com `value` diferente = **changed**. Cada evento recebe uma
**severidade**, e **cada canal** aplica o seu próprio limiar de nível.

A severidade é **contextual e explicável** (`levels.assess`), com **confiança**
como dimensão **independente** (`severity` = impacto; `confidence` = quão confiável
é a observação). Parte de uma base por categoria e é **elevada por regras nomeadas**,
usando o **contexto do ativo** (`context.assets`: `exposure`, `criticality`,
`expected_ports`, `forbidden_ports`): porta administrativa/dados recém-exposta
(RDP, VNC, Redis…) → `critical`; porta **proibida** pela política → `critical`;
porta **fora do estado esperado** → `high`; DMARC `p=none` → `high`. Cada
avaliação carrega **reason codes** estáveis (`NEW_OPEN_PORT`, `INTERNET_EXPOSED_ASSET`,
`FORBIDDEN_PORT`…) e um `rule_id` — o painel e o webhook mostram o **porquê**.
Um **CHANGED** ainda traz o diff **por campo** (`_changes`: `status: 200 → 403`),
e cada evento carrega **proveniência** (`_source`/vantage, `_collector`).

> [!IMPORTANT]
> **Ausência só vira `removed` quando o escopo foi observado com sucesso.** Cada
> collector devolve `ok=True/False`; se a coleta de um host/categoria falhou
> (timeout, fonte indisponível), aquele escopo **não** gera `removed` — o estado
> anterior é preservado. Uma falha transitória de rede nunca apaga sua superfície.
> E o **primeiro scan** de um alvo é gravado como **baseline** (estado, zero
> eventos), então o histórico e a tendência não começam com "tudo é novo".

Fontes de subdomínio (passivas, Certificate Transparency):
`crt.name` e `crt.sh`. O parser é defensivo — extrai hostnames válidos sob o
apex independente do formato exato da resposta.

### Sinais de postura (headers, tech, favicon)

Reaproveitando o **mesmo GET** do collector HTTP (sem custo extra), o Padmé
registra a **postura de cabeçalhos de segurança** (`HTTPSEC`: HSTS, CSP,
X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy — o `value` lista o
que **falta**) e um **fingerprint de tecnologia** leve no metadata do HTTP
(nginx, Cloudflare, PHP…), derivado só de cabeçalhos. Um GET extra a
`/favicon.ico` gera um **hash de favicon** (`FAVICON`, `sha256/16`) para
**pivotar infraestrutura** — dois hosts com o mesmo hash tendem a compartilhar a
mesma stack. Tudo respeita o `ok`/escopo: coleta inconclusiva **não** vira
`removed`.

### Subdomain takeover

Para cada host com **CNAME**, a Padmé casa o alvo contra uma base de serviços
(baseada no **can-i-take-over-xyz**: GitHub Pages, S3, Heroku, Azure, Shopify,
Fastly, Zendesk, etc.) e confirma de dois jeitos:

- **fingerprint** — busca o corpo HTTP e casa a assinatura de "recurso não
  reivindicado" (ex: *"There isn't a GitHub Pages site here."*);
- **nxdomain** — para serviços tipo Azure, se o alvo do CNAME não resolve, o
  apontamento está *dangling* → vulnerável.

Host sem CNAME nem entra na checagem (custo zero). Um achado vira um evento
`TAKEOVER`, que aparece no **topo** do alerta (severidade `critical`).

### Expiração de certificado

O collector de TLS parseia o certificado (via `cryptography`, então funciona
até em cert self-signed ou já expirado) e, se ele estiver a **≤ N dias** de
expirar (`collectors.cert_expiry_days`, padrão 14), emite um evento
`CERT_EXPIRY` (severidade `high`). O valor gravado é estável (a data), então
você recebe **um** aviso ao entrar na janela — não um por dia. Se expirar de
vez, o evento vira `EXPIRADO`.

O TLS também captura os **SANs** do certificado (`subjectAltName`). Como o
fingerprint entra no valor, toda reemissão dispara um `CHANGED` — e o diff por
campo mostra **quais domínios entraram/saíram do cert** (um SAN novo costuma ser
superfície nova servida ali). Os SANs também vão na evidência (`tls_handshake`).

### Segurança operacional

- **Segredos fora dos logs.** `httpx`/`httpcore` são silenciados (a request line
  com o token do bot / secret do webhook não é logada) e um filtro mascara
  qualquer segredo conhecido que apareça em log — mesmo com `-v`.
- **Anti-SSRF (`network.follow_redirects`, padrão `false`).** Um `Location:
  http://127.0.0.1/` não é seguido; o destino é apenas registrado.
- **IP privado/reservado (`network.allow_private_ips`, padrão `false`).** Hosts
  que resolvem para faixas internas (10/8, 192.168/16, 127/8, link-local, ULA
  IPv6…) **não** são sondados ativamente (HTTP/TLS/portas). O DNS passivo segue.
  Ligue conscientemente só se for monitorar rede interna.
- **Teto de corpo HTTP (`collectors.max_response_bytes`, 256 KiB).** O collector
  lê por streaming e descarta o resto — um endpoint de 500 MB não estoura memória.
- **Pacing responsável (`network.rate_limit_rps` / `per_host_interval_ms` /
  `jitter_ms`, padrão desligado).** Teto global de requisições/segundo com jitter
  e intervalo mínimo por host — o monitor 24/7 não martela o alvo nem dispara
  WAF/rate-limit. Não aumenta agressividade; só torna o scan previsível e educado.
- **Retry educado (`network.max_retries`, padrão `2`).** Requisições HTTP do scan
  recuam com backoff exponencial + jitter em `429`/`5xx` transitório (respeitando
  `Retry-After`) e em hiccup de conexão/timeout. `4xx` permanente nunca repete.
- **Painel seguro por padrão.** Bind em `127.0.0.1`; um token opcional
  (`PADME_WEB_TOKEN`) exige `Authorization: Bearer` em **todas** as rotas
  (`/`, `/export`, `/vantage`), validado em tempo constante. Servir fora de
  localhost **sem** token é **recusado** (a menos de `--allow-no-auth`) — expor a
  superfície é decisão consciente. As respostas trazem headers de segurança
  (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`,
  CSP). Ver [`docs/RUNBOOK.md`](docs/RUNBOOK.md) para o painel atrás de proxy + TLS.

---

## Instalação

```bash
git clone <seu-repo> padme && cd padme
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt         # ou: pip install -e .
cp config.example.yaml config.yaml      # e edite
```

Ou instale como comando isolado, sem mexer no seu Python, com **pipx**:

```bash
pipx install .                          # do diretório do repo (usa o pyproject)
# ou direto do Git:
pipx install "git+https://github.com/LuizWT/PADME.git"
padme --version
```

## Docker (sentinela 24/7)

O modo de uso principal é rodar em loop com **restart automático**. Com Docker o
deploy vira um comando; a config, o `.env` e o `padme.db` ficam num volume em
`/data`.

```bash
# 1) build
docker build -t padme .

# 2) prepare a config num diretório que será montado em /data
mkdir -p data && cp config.example.yaml data/config.yaml   # edite os alvos/canais
#    (opcional) segredos em data/.env — são lidos sozinhos

# 3) rode o sentinela em background, reiniciando sozinho
docker run -d --name padme --restart unless-stopped \
    -v "$PWD/data:/data" --user "$(id -u):$(id -g)" padme monitor

docker logs -f padme
```

Comandos avulsos usam a mesma imagem — ex.: `docker run --rm -v "$PWD/data:/data" \
--user "$(id -u):$(id -g)" padme test-notify`.

Ou, mais simples, com **docker compose** (o `docker-compose.yml` já traz
`restart: unless-stopped`):

```bash
mkdir -p data && cp config.example.yaml data/config.yaml   # edite
docker compose up -d
docker compose logs -f
```

> [!TIP]
> `--user "$(id -u):$(id -g)"` faz o `padme.db` sair com o dono certo no host.
> No compose, ajuste `user:` se o seu `id -u`/`id -g` não for `1000`.

## Configuração do Telegram

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

## Uso

```bash
# Scan único — grava/atualiza o baseline e imprime as mudanças
python -m padme scan

# Scan único que também dispara alerta no Telegram
python -m padme scan --notify

# Modo sentinela: varre em loop e alerta no Telegram (roda uma vez e esquece)
python -m padme monitor

# Sobrescrevendo intervalo e nível na hora
python -m padme monitor --interval 600 --level high

# Um único ciclo e sai (ideal p/ cron) + lock de instância única (não sobrepõe)
python -m padme monitor --once --lock /tmp/padme.lock

# Ver o histórico de eventos gravados
python -m padme events --limit 50

# Exportar o estado atual (JSON no stdout, ou CSV para um arquivo)
python -m padme export --format json
python -m padme export --format csv --out superficie.csv

# Painel web read-only (lê o padme.db; atualiza sozinho a cada 30s)
python -m padme web            # http://127.0.0.1:8787 (localhost, sem token)

# Painel com token (exige Authorization: Bearer em todas as rotas)
export PADME_WEB_TOKEN="$(openssl rand -hex 32)"
python -m padme web

# Testar todos os canais de notificação configurados
python -m padme test-notify

# Diagnóstico: integridade do banco, saúde dos scans por alvo e avisos de config
python -m padme doctor

# Multi-vantage: consolidar exports de várias máquinas/IPs e ver divergências
python -m padme merge casa.json vps-eu.json --out consolidado.json
```

> O painel aceita **filtro por domínio** (`?target=alvo.com` ou o dropdown no
> topo) e uma visão **multi-vantage** em `/vantage` quando `web.vantage_dir`
> aponta para exports de outras fontes (consolida com o `padme merge`).

> Se instalar com `pip install -e .`, o comando `padme` fica disponível
> direto (sem o `python -m`).

## Níveis de notificação (por canal)

O **terminal sempre mostra tudo**. Cada **canal** tem o seu próprio limiar
mínimo de severidade — não existe mais um "nível global do Telegram":

| Nível | Envia |
|---|---|
| `critical` | só **takeover** |
| `high` | takeover + **porta/subdomínio novo** + cert expirando + **wildcard DNS** |
| `medium` *(padrão)* | acima + **HTTP/TLS mudou**, serviço novo |
| `low` | acima + remoções e mudanças menores |
| `debug` | **tudo**, inclusive registros DNS |

```yaml
telegram: { level: medium }   # padrão
discord:  { level: low }
webhook:  { level: debug }    # sink de automação recebe o fluxo completo
email:    { level: high }     # e-mail só o que importa
```

Padrões: `telegram`/`discord`/`email` = `medium`; `webhook` = `debug`. `--level`
na CLI sobrescreve o do **Telegram**. Cada canal filtra de forma independente, e
o envio é **concorrente** (um canal lento/quebrado não segura os outros).

## Canais de notificação

Os alertas vão para **todos** os canais habilitados, cada um filtrando pelo seu
nível, com **retry** (timeout/429/5xx, com backoff e respeito a `Retry-After`;
nunca em 4xx):

- **Telegram** — formatação HTML estilo diff, com blocos recolhíveis.
- **Discord** — cole a URL de um *Webhook* de canal em `discord.webhook_url`
  (mensagem em Markdown).
- **E-mail** — SMTP com STARTTLS (`email.*`). Para Gmail, use uma *App
  Password*. Corpo em texto puro.
- **Webhook genérico** — `webhook.url` recebe um **JSON estruturado** a cada
  mudança, ideal para **n8n** e automações. Aceita `headers` opcionais (ex.: um
  token de auth) e cada evento traz `event_id`/`scan_id`/`detected_at` (UTC) para
  deduplicação e troubleshooting:

  ```json
  {
    "schema_version": 1,
    "source": "padme",
    "type": "changes",
    "target": "alvo.com",
    "scan_id": "9f2c…",
    "time": "2026-09-26T00:46:00+00:00",
    "count": 2,
    "events": [
      {"event_id": "a1b2…", "scan_id": "9f2c…",
       "detected_at": "2026-09-26T00:46:00+00:00",
       "severity": "critical", "confidence": "confirmed",
       "risk": {"rule_id": "high-risk-port-added",
                "reasons": ["NEW_OPEN_PORT", "REMOTE_ACCESS_SERVICE", "INTERNET_EXPOSED_ASSET"]},
       "kind": "port", "type": "added", "key": "vpn.alvo.com:3389", "old": null, "new": "open",
       "evidence": {"type": "tcp_connect", "state": "open", "port": 3389},
       "source": "vps-eu", "context": {"exposure": "internet", "criticality": "critical"}}
    ],
    "text": "**PADMÉ** · `alvo.com` ..."
  }
  ```

  > Contrato **aditivo** (`schema_version` só muda se algum campo for removido):
  > `confidence`, `risk.rule_id`/`risk.reasons` (códigos estáveis), `source`,
  > `context`, `evidence` (a prova normalizada — `tcp_connect`/`http_response`/
  > `tls_handshake`/`takeover_check`/`dns_record`…) e, em `CHANGED`, `changes`
  > (diff por campo) foram **acrescentados**.

Todos aceitam `${VAR}` do `.env` (ex: `webhook_url: ${PADME_DISCORD_WEBHOOK}`).
Teste todos de uma vez com `python -m padme test-notify`.

## Rodando 24/7

- **Docker / compose** (recomendado): `docker compose up -d` — restart
  automático embutido. Ver a seção [Docker](#docker-sentinela-247).
- **systemd** (em servidor sem Docker): unit completa com hardening, backup do
  SQLite, rotação de segredos e painel atrás de proxy+TLS estão no
  **[runbook operacional](docs/RUNBOOK.md)**.
- **cron + `monitor --once --lock`**: se preferir não deixar processo vivo,
  agende `padme monitor --once --lock /tmp/padme.lock` — um ciclo por vez, sem
  sobrepor execuções (o `--lock` sai na hora se o ciclo anterior ainda roda).
- **tmux/screen**: pro rápido e sujo.

> [!NOTE]
> **Heartbeat / dead-man's switch.** Um processo morto não avisa que morreu —
> por isso o sinal de vida vai pra fora. Configure `heartbeat.url`
> (healthchecks.io, Uptime Kuma, cronitor…) e a Padmé faz um ping a cada N
> ciclos; se o ping some, o watchdog **externo** te alerta. Um ciclo com falha
> vira ping em `url/fail`. Opcionalmente `heartbeat.file` grava o timestamp da
> última vida localmente.

---

## Retenção do histórico

O `state` (foto atual) nunca é apagado. O histórico de **eventos** pode crescer
sem limite em 24/7 — defina `storage.event_retention_days` (0 = mantém tudo) e o
monitor poda os eventos antigos a cada ciclo.

## Release limpo

Nunca zipe a pasta na mão (arrastaria `.env`, `config.yaml`, `padme.db`). Use
`git archive`, que só empacota o que está versionado:

```bash
sh scripts/release.sh            # gera padme-<ver>.tar.gz e lista o conteúdo
```

## Testes

```bash
pip install pytest ruff
ruff check padme tests           # lint (o CI roda em Python 3.10/3.11/3.12)
pytest -q                        # 212 testes
```

## Estrutura

```
padme/
├── padme/
│   ├── cli.py            # comandos scan / monitor / events / export / web / doctor / backup / merge
│   ├── config.py         # carrega e valida o YAML (collectors/network/storage/canais)
│   ├── models.py         # Record / Event / Kind / CollectionResult / scope_of
│   ├── levels.py         # severidade base + assess() (severity+confidence+reason codes)
│   ├── context.py        # contexto de ativo por config (criticality/exposure/ports)
│   ├── evidence.py       # evidência normalizada por evento (tcp_connect/http_response…)
│   ├── netpolicy.py      # política de rede: IP privado/reservado + redirect (anti-SSRF)
│   ├── ratelimit.py      # pacing responsável: rps global + jitter + intervalo por host
│   ├── logredact.py      # redação de segredos nos logs
│   ├── storage.py        # SQLite: estado + histórico + saúde + migrações (user_version)
│   ├── merge.py          # consolidação multi-vantage (padme merge)
│   ├── alerts.py         # amortecimento de flapping
│   ├── differ.py         # engine de diff (puro, testável)
│   ├── engine.py         # orquestra collectors + escopos observados + diff
│   ├── scheduler.py      # loop do modo sentinela (monitor) + heartbeat + retenção
│   ├── heartbeat.py      # dead-man's switch (ping de watchdog + arquivo de vida)
│   ├── singleton.py      # lock de instância única (fcntl/msvcrt) p/ cron
│   ├── webpanel.py       # painel read-only (auth Bearer) + tendência + /vantage (stdlib)
│   ├── collectors/       # subdomains, bruteforce, wildcard, dns, dnsrecon (NS/SPF/DMARC),
│   │                     #   http (+ headers de segurança/tech), favicon (hash), tls,
│   │                     #   takeover, ports (com banner-grab)
│   └── notify/           # base (Protocol/Manager/retry), formatting, telegram, webhook, email
├── docs/RUNBOOK.md       # operação: systemd, backup, rotação de segredos, proxy+TLS
├── .github/workflows/    # CI: ruff + compileall + pytest (matriz 3.10/3.11/3.12)
├── scripts/release.sh    # release limpo via git archive
├── Dockerfile            # imagem do sentinela (roda `padme`)
├── docker-compose.yml    # sobe o monitor 24/7 com restart automático
├── .dockerignore
├── config.example.yaml
├── requirements.txt
├── pyproject.toml
└── tests/                # 212 testes: unitários + reliability + netpolicy +
                          # logredact + dispatch/retry + collectors_ok + integração
```
