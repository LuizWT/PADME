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
- **Detecção de subdomain takeover** (CNAME dangling + fingerprints, e CNAME
  para **domínio não registrado** mesmo fora da base de serviços).
- **Sinais RED**: mudança de **NS** (delegação / hijack de zona), **SPF/DMARC**
  (remoção = domínio spoofável; SPF `+all`/`?all` e DMARC `p=none`/`sp=none`
  viram `high` e aparecem nos problemas abertos do painel) e **banner-grab** nas portas (mudança de banner
  = versão de serviço mudou). Além do texto de saudação (SSH/SMTP/FTP…), o
  handshake binário do **MySQL/MariaDB** é decodificado para a versão exata do
  servidor — banco exposto com versão conhecida é sinal forte.
- **Multi-vantage**: cada instância é um `source`; `padme merge` consolida os
  exports e mostra **divergências** entre pontos de observação (geo-block,
  split-horizon, host que só aparece de um lugar).
- **Metadata estruturada** por evento (issuer/expira/fingerprint/SANs, status/server,
  porta service/product/version, service/reason…) no painel, na evidência e no
  webhook — n8n consome campos, não parseia string.
- **Amortecimento de flapping**: chave que oscila para de spammar (segue no
  histórico). **Validação forte de config** (falha cedo com mensagem clara).
- **Aviso de expiração de certificado TLS** (antes de virar incidente).
- **Bruteforce de subdomínios** por wordlist (opcional) + CT logs.
- **Qualidade de sinal**: subdomínio `live`/`quiet` + **detecção de wildcard DNS**
  (suprime a inundação de falso-positivo do bruteforce em apex catch-all).
  Registros DNS são **agregados por host e tipo** (`host|A` = conjunto de IPs):
  a rotação de IP de uma CDN vira **um** `changed` com o diff do conjunto, em vez
  de um par removido/adicionado por IP a cada ciclo.
- **Export** para JSON/CSV e **painel web** só-leitura, com **gráfico de
  tendência** (eventos/dia nos últimos 30d, sem registros DNS) — enxerga a
  superfície crescer/encolher.
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

A severidade é **contextual e explicável** (`risk.assess`), com **confiança**
como dimensão **independente** (`severity` = impacto; `confidence` = quão confiável
é a observação). Parte de uma base por categoria e é **elevada por regras nomeadas**,
usando o **contexto do ativo** (`context.assets`: `exposure`, `criticality`,
`expected_ports`, `forbidden_ports`): porta administrativa/dados recém-exposta
(RDP, VNC, Redis…) → `critical`; porta **proibida** pela política → `critical`;
porta **fora do estado esperado** → `high`; DMARC `p=none`/`sp=none` e SPF
`+all`/`?all` → `high`. Cada
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
> eventos), então o histórico e a tendência não começam com "tudo é novo". Se a
> baseline vier de uma coleta parcial, ela fica **provisória** e consolida no scan
> seguinte, sem virar uma enxurrada de "novo".
>
> Subdomínio segue a mesma regra: sumir do CT ou do bruteforce **não** é remoção.
> Um subdomínio conhecido continua sendo inspecionado e só sai do estado quando
> o **DNS dele** é observado e o nome não resolve mais. O rótulo `live`/`quiet`
> também só muda com prova — um timeout de HTTP não rebaixa o host para `quiet`.
>
> A saúde da coleta separa os dois casos: **erro** (um collector quebrou) marca o
> alvo como *dados parciais*; **inconclusivo** (sem resposta, estado preservado)
> não, mas aparece no painel e no `doctor` — ex.: *coleta ok · 3 inconclusivos*.

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

CNAME para um serviço **fora da base** também é checado: se o alvo não resolve
(NXDOMAIN) **e** o domínio registrável dele não existe (consulta NS → NXDOMAIN),
qualquer um pode registrar esse domínio e responder pelo seu host — achado
`critical` com confiança `high` (inferência por DNS, sem fingerprint). Alvo
inexistente dentro de um domínio que **existe** não é reivindicável por
terceiro e não gera alerta; resposta inconclusiva (timeout) nunca vira achado.

A base de serviços é **dado**, não código: `padme/data/takeover_fingerprints.json`,
com a data da última revisão (`reviewed`). O `padme doctor` avisa quando ela
passa de 180 dias sem revisão contra o can-i-take-over-xyz.

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

Com o scan de portas ligado, o certificado também é lido nas portas de **TLS
implícito** que estiverem abertas (8443, 9443, 6443, 993, 995, 465, 636, 853,
990, 2376, 5986) — painel de admin em 8443 e IMAPS/SMTPS têm cert próprio, com
expiração própria. O escopo de TLS do host só gera `removed` quando a 443, cada
porta extra **e** o próprio scan de portas foram observados.

### Segurança operacional

- **Segredos fora dos logs.** `httpx`/`httpcore` são silenciados (a request line
  com o token do bot / secret do webhook não é logada) e um filtro mascara
  qualquer segredo conhecido que apareça em log — mesmo com `-v`.
- **Anti-SSRF (`network.follow_redirects`, padrão `false`).** Um `Location:
  http://127.0.0.1/` não é seguido; o destino é apenas registrado. Ligando o
  follow, cada salto é seguido manualmente (até 5) e validado **antes** da
  requisição: só `http`/`https`, e o destino (IP literal ou nome resolvido)
  precisa ser público. Salto bloqueado fica registrado como redirect.
- **IP privado/reservado (`network.allow_private_ips`, padrão `false`).** Hosts
  que resolvem para faixas não-públicas (10/8, 192.168/16, 127/8, link-local,
  CGNAT 100.64/10, ULA IPv6, IPv4 embutido em IPv6…) **não** são sondados
  ativamente (HTTP/TLS/portas). O DNS passivo segue. Limite: a checagem resolve
  antes da conexão, então não é defesa completa contra DNS rebinding.
  Ligue conscientemente só se for monitorar rede interna.
- **Teto de corpo HTTP (`collectors.max_response_bytes`, 256 KiB).** O collector
  lê por streaming e descarta o resto — um endpoint de 500 MB não estoura memória.
- **Pacing responsável (`network.rate_limit_rps` / `per_host_interval_ms` /
  `jitter_ms`, padrão desligado).** Teto global de sondas/segundo com jitter e
  intervalo mínimo por host, aplicado a **toda sondagem ativa**: requisições
  HTTP, connects de porta, handshakes TLS e consultas do bruteforce — o monitor
  24/7 não martela o alvo nem dispara WAF/rate-limit. Não aumenta agressividade;
  só torna o scan previsível e educado.
- **Teto de connects de porta (`network.max_parallel_connects`, padrão `256`).**
  Limita quantas conexões TCP do scan de portas ficam abertas ao mesmo tempo,
  somando todos os hosts — uma lista grande de portas não esgota os file
  descriptors da máquina nem vira rajada contra o alvo.
- **Retry educado (`network.max_retries`, padrão `2`).** Requisições HTTP do scan
  recuam com backoff exponencial + jitter em `429`/`5xx` transitório (respeitando
  `Retry-After`) e em hiccup de conexão/timeout. `4xx` permanente nunca repete.
- **Painel seguro por padrão.** Bind em `127.0.0.1`; um token opcional
  (`PADME_WEB_TOKEN`) protege **todas** as rotas (`/`, `/export`, `/vantage`),
  validado em tempo constante. No **navegador**, o login aparece sozinho: qualquer
  usuário, o token como senha (HTTP Basic). Em automação, `Authorization: Bearer`.
  Servir fora de localhost **sem** token é **recusado** (a menos de
  `--allow-no-auth`) — expor a superfície é decisão consciente. O painel abre o
  banco **só para leitura** (nunca escreve nem migra; banco em versão antiga
  responde 503 até o monitor migrar), cada conexão tem timeout e há um teto de
  conexões simultâneas. As respostas trazem headers de segurança (`nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`, CSP).

  > [!WARNING]
  > Token por HTTP puro trafega em claro (Basic e Bearer). Fora de localhost,
  > sirva atrás de um proxy com TLS — ver [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## Instalação

```bash
git clone <seu-repo> padme && cd padme
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt         # ou: pip install -e .
cp config.example.yaml config.yaml      # e edite
```

> [!NOTE]
> O `requirements.txt` é um **lock com versões fixas** (inclusive dependências
> transitivas), o mesmo que a imagem Docker e o CI instalam — build reproduzível.
> O `pyproject.toml` mantém faixas compatíveis para quem instala como pacote.
> O CI roda `pip-audit` sobre o lock a cada push.

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

> [!NOTE]
> A imagem traz um `HEALTHCHECK` (`padme health`): o container fica `unhealthy`
> se o último scan passou de `2*interval_seconds + 10min` (loop travado, banco
> inacessível). `docker stop` manda SIGTERM, tratado como o Ctrl+C: o monitor
> avisa "monitoramento encerrado" nos canais e fecha o banco antes de sair.

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

Teste (envia uma mensagem de teste para **todos** os canais configurados):

```bash
python -m padme test-notify
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

# Painel com token (navegador: login com o token como senha; API: Bearer)
export PADME_WEB_TOKEN="$(openssl rand -hex 32)"
python -m padme web

# Testar todos os canais de notificação configurados
python -m padme test-notify

# Diagnóstico: integridade do banco, saúde dos scans por alvo e avisos de config
python -m padme doctor

# Liveness (exit 0/1, sem rede): o último scan é recente? Para HEALTHCHECK/cron
python -m padme health                 # limite padrão: 2*interval_seconds + 10min
python -m padme health --max-age 7200

# Multi-vantage: consolidar exports de várias máquinas/IPs e ver divergências
python -m padme merge casa.json vps-eu.json --out consolidado.json
```

> O painel aceita **filtro por domínio** (`?target=alvo.com` ou o dropdown no
> topo) e uma visão **multi-vantage** em `/vantage` quando `web.vantage_dir`
> aponta para exports de outras fontes (consolida com o `padme merge`).

> [!TIP]
> No multi-vantage, atualize todas as instâncias juntas: a partir desta versão o
> DNS é exportado agregado (`host|A`), então comparar com export de versão
> anterior (`host|A|ip`) aparece como divergência de presença até todas migrarem.

> Se instalar com `pip install -e .`, o comando `padme` fica disponível
> direto (sem o `python -m`).

## Níveis de notificação (por canal)

O **terminal sempre mostra tudo**. Cada **canal** tem o seu próprio limiar
mínimo de severidade — não existe mais um "nível global do Telegram":

| Nível | Envia |
|---|---|
| `critical` | só **takeover** |
| `high` | takeover + **porta/subdomínio novo** + cert expirando + **wildcard DNS** |
| `medium` *(padrão)* | acima + **HTTP/TLS mudou**, serviço novo, **takeover corrigido** |
| `low` | acima + remoções, mudanças menores, cert renovado |
| `debug` | **tudo**, inclusive registros DNS |

> [!NOTE]
> Resolução não herda a gravidade do problema. **Takeover corrigido** entra como
> `medium`: chega aos canais padrão como aviso de resolução (razão
> `ISSUE_RESOLVED`), não como alerta crítico. **Certificado renovado** e troca de
> IP do catch-all de wildcard entram como `low`.

```yaml
telegram: { level: medium }   # padrão
discord:  { level: low }
webhook:  { level: debug }    # sink de automação recebe o fluxo completo
email:    { level: high }     # e-mail só o que importa
```

Padrões: `telegram`/`discord`/`email` = `medium`; `webhook` = `debug`. `--level`
na CLI sobrescreve o do **Telegram**. Cada canal filtra de forma independente, e
o envio é **concorrente** (um canal lento/quebrado não segura os outros).

> [!IMPORTANT]
> **Alerta grave não se perde em silêncio.** Se um canal falha ao entregar um
> evento `high` ou `critical` (Telegram fora do ar, token trocado…), o evento
> entra numa fila no banco e é reenviado **a esse canal** no ciclo seguinte do
> `monitor` — inclusive depois de um reinício. Após 5 tentativas ou 24h, o PADME
> desiste com log de erro. O `padme doctor` mostra o que está aguardando reenvio.

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

  **Assinatura (opcional, `webhook.secret`).** Com o segredo definido, cada POST
  leva `X-Padme-Timestamp` (unix) e `X-Padme-Signature: sha256=<hex>` — o
  HMAC-SHA256 de `"<timestamp>.<corpo>"`. O destino confere que a mensagem veio
  do PADME, que não foi alterada, e recusa timestamp velho (replay). Valide sobre
  os **bytes crus** do corpo, antes de parsear o JSON:

  ```python
  import hashlib, hmac, time

  def veio_do_padme(secret: bytes, headers, body: bytes, janela=300) -> bool:
      ts = headers["X-Padme-Timestamp"]
      if abs(time.time() - int(ts)) > janela:
          return False                      # reenvio velho (replay)
      esperado = "sha256=" + hmac.new(secret, ts.encode() + b"." + body,
                                      hashlib.sha256).hexdigest()
      return hmac.compare_digest(esperado, headers["X-Padme-Signature"])
  ```

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
pip install -r requirements-dev.txt   # lock + pytest/ruff/pip-audit fixos
ruff check padme tests           # lint (o CI roda em Python 3.10/3.11/3.12)
pytest -q
pip-audit -r requirements.txt    # CVEs conhecidas nas dependências fixas
```

## Estrutura

```
padme/
├── padme/
│   ├── cli.py            # comandos scan / monitor / events / export / web / doctor / health / backup / merge
│   ├── config.py         # carrega e valida o YAML (collectors/network/storage/canais)
│   ├── models.py         # Record / Event / Kind / CollectionResult / scope_of
│   ├── risk.py           # motor de risco: severidade base + assess() (severity+confidence+reason codes)
│   ├── portmap.py        # tabela única de portas: serviço, risco (acesso remoto/dados), TLS implícito
│   ├── mailpolicy.py     # leitura de SPF (qualificador do all) e DMARC (p/sp)
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
│   ├── scheduler.py      # ciclo por alvo (scan_one, usado por monitor e scan) + reenvio + heartbeat
│   ├── heartbeat.py      # dead-man's switch (ping de watchdog + arquivo de vida)
│   ├── singleton.py      # lock de instância única (fcntl/msvcrt) p/ cron
│   ├── webpanel.py       # painel só-leitura (auth Basic/Bearer) + tendência + /vantage (stdlib)
│   ├── panel_metrics.py  # dados dos cartões: problemas, priorização, KPIs §27 (sem HTML)
│   ├── panel_assets.py   # CSS e JS do painel (strings estáticas)
│   ├── collectors/       # subdomains, bruteforce, wildcard, dns, dnsrecon (NS/SPF/DMARC),
│   │                     #   http (+ headers de segurança/tech), favicon (hash), tls,
│   │                     #   takeover, ports (com banner-grab)
│   ├── data/             # takeover_fingerprints.json (base revisável, com data)
│   └── notify/           # base (Protocol/Manager/retry), formatting, telegram, webhook, email
├── docs/RUNBOOK.md       # operação: systemd, backup, rotação de segredos, proxy+TLS
├── ideias.md             # evolução adiada por design (porquê/como/impacto)
├── .github/workflows/    # CI: ruff + compileall + pytest (3.10/3.11/3.12) + pip-audit
├── scripts/release.sh    # release limpo via git archive
├── Dockerfile            # imagem do sentinela (roda `padme`)
├── docker-compose.yml    # sobe o monitor 24/7 com restart automático
├── .dockerignore
├── config.example.yaml
├── requirements.txt      # lock com versões fixas (Docker/CI)
├── requirements-dev.txt  # lock + ferramentas de teste/lint/auditoria
├── pyproject.toml
└── tests/                # 356 testes: unitários + reliability + netpolicy +
                          # logredact + dispatch/retry + collectors_ok + integração
```
