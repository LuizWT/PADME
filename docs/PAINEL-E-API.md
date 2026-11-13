# Painel web, problemas e API

[Voltar ao README](../README.md)

- [Painel](#painel)
- [Abrir o painel na rede](#abrir-o-painel-na-rede)
- [Problemas (findings)](#problemas-findings)
- [API JSON](#api-json)
- [Várias máquinas (multi-vantage)](#várias-máquinas-multi-vantage)

## Painel

O painel abre junto com o monitor, em http://127.0.0.1:8787:

```bash
padme                    # monitor + painel
padme --web-port 9000    # outra porta
padme --no-web           # sem painel
padme web                # só o painel (lê o banco; não varre nada)
```

O que mostra:

- **Visão geral**: problemas abertos ordenados por risco, atividade dos
  últimos 30 dias e a saúde de cada coletor.
- **Alvos**: tabela com o estado de cada domínio e um dossiê por alvo
  (risco aberto, saúde da coleta, linha do tempo com o diff e o inventário).
- Filtro por domínio no topo (ou `?target=alvo.com` na URL).

**Tempo real.** Quando uma varredura grava algo no banco, o painel se atualiza
sozinho em cerca de um segundo, sem recarregar a página e sem perder filtro,
rolagem ou seções abertas. O indicador no canto mostra o estado:

| Indicador | Significado |
|---|---|
| ao vivo | conectado; atualiza a cada mudança |
| em espera | você está digitando ou com o menu de ações aberto; atualiza quando terminar |
| reconectando / sem conexão | perdeu a conexão com o Padmé; tenta de novo sozinho |
| atualizando a cada 30 s | o navegador não manteve a conexão ao vivo (ex.: proxy que corta); atualiza por tempo |

O painel abre o banco **só para leitura**. A única escrita são as ações de
problema (abaixo).

## Abrir o painel na rede

Por padrão o painel só aceita conexões desta máquina (`127.0.0.1`). Para abrir
em outra máquina da rede, defina um token e o endereço:

```yaml
web:
  bind: 0.0.0.0
  token: ${PADME_WEB_TOKEN}
```

```dotenv
# .env  (gere com: python -c "import secrets; print(secrets.token_hex(32))")
PADME_WEB_TOKEN=coloque-um-valor-longo-e-aleatorio
```

- No navegador aparece um login: qualquer usuário, o token como senha.
- Em scripts: `Authorization: Bearer <token>`.
- Sem token, o Padmé **se recusa** a servir fora de localhost (o monitor
  continua rodando, só sem painel). `--allow-no-auth` força, se for mesmo isso
  que você quer.

> [!WARNING]
> O painel não tem HTTPS: fora de localhost, o token trafega em claro. Para
> acesso pela internet, coloque um proxy com TLS na frente (nginx ou Caddy).
> Exemplos no [RUNBOOK](RUNBOOK.md#5-painel-web-atrás-de-proxy-tls).

Outras proteções: comparação do token em tempo constante, limite de conexões
simultâneas, timeout por conexão e cabeçalhos de segurança (CSP,
`X-Frame-Options: DENY`, `nosniff`, `no-store`).

## Problemas (findings)

Takeover, certificado expirando, curinga de DNS e política de e-mail fraca viram
**problemas** com id estável: o mesmo problema mantém o id entre varreduras.

| Status | Quando | Conta como aberto | Notifica |
|---|---|---|---|
| `aberto` | detectado (ou voltou) | sim | sim |
| `reconhecido` | alguém viu e vai tratar | sim | sim |
| `silenciado` | falso positivo (exige motivo) | não | não |
| `risco aceito` | decisão consciente (exige motivo) | não | não |
| `resolvido` | sumiu na varredura (só a varredura resolve) | não | |

```bash
padme finding list                                   # os que pedem ação
padme finding list --all                             # inclui tratados e resolvidos
padme finding show 4a3cadf8                          # detalhes e histórico
padme finding ack 4a3cadf8                           # id ou os 6+ primeiros caracteres
padme finding suppress 4a3cadf8 --reason "CNAME nosso, em manutenção"
padme finding accept 5d9a787e --reason "curinga do CDN, esperado"
padme finding reopen 4a3cadf8
```

No painel, cada problema tem um menu **ações** com as mesmas opções.

- **Reabre sozinho**: um problema resolvido que volta fica `aberto` de novo.
  Silenciado ou aceito que some e volta continua tratado.
- **Prazo**: `findings.sla_hours` define horas por severidade (padrão: crítico
  24h, alto 72h, médio 7 dias). Reconhecer não para o relógio; passou do prazo,
  aparece como "prazo estourado".
- **Histórico**: toda mudança guarda de/para, quem e por quê. No painel com
  token, o usuário do login entra como autor.

> [!IMPORTANT]
> As ações do painel usam token CSRF e checagem de origem. Ficam desligadas
> sozinhas se o painel estiver exposto sem token; `web.actions: false` deixa o
> painel só leitura.

## API JSON

Para integrar com SIEM, ticketing ou scripts: `padme api` serve uma API REST
somente leitura em http://127.0.0.1:8788/api/v1.

| Rota | Devolve |
|---|---|
| `GET /api/v1` | metadados e lista de rotas |
| `GET /api/v1/surface` | estado atual (os campos do `padme export`) |
| `GET /api/v1/events` | eventos com severidade, confiança e motivo (o mesmo formato do webhook) |
| `GET /api/v1/health` | saúde por alvo (última varredura, inconclusivos) |
| `GET /api/v1/findings` | problemas com status, prazo, motivo e autor |

Filtros: `?target=`, `?kind=`; em `events`, `?type=added|removed|changed`,
`?min_severity=high` e `?since=` (unix ou ISO-8601); em `findings`, `?status=`
(repetível; `all` traz todos). Paginação com `?limit=` (até 1000) e `?offset=`.

```bash
curl -s -H "Authorization: Bearer $PADME_API_TOKEN" \
  "http://127.0.0.1:8788/api/v1/events?min_severity=high&target=alvo.com"
```

A autenticação segue a regra do painel: sem token, só localhost. O token é
`api.token` (`PADME_API_TOKEN`) ou, se vazio, o do painel. Toda resposta traz
`schema_version`; campos novos podem aparecer, mas não somem.

## Várias máquinas (multi-vantage)

O mesmo alvo pode parecer diferente de lugares diferentes (bloqueio por país,
DNS split-horizon, host visível só de uma rede). Rode o Padmé em mais de uma
máquina, cada uma com seu `source` no config, e compare os exports:

```bash
padme export --out casa.json          # em cada máquina
padme merge casa.json vps-eu.json --out consolidado.json
```

O `merge` mostra o que só aparece de um ponto de observação. No painel, aponte
`web.vantage_dir` para uma pasta com os exports e abra `/vantage`.
