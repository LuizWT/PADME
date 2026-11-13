# O que o Padmé detecta e como

[Voltar ao README](../README.md)

- [Como uma mudança vira alerta](#como-uma-mudança-vira-alerta)
- [Severidade](#severidade)
- [Subdomínios](#subdomínios)
- [HTTP, TLS e portas](#http-tls-e-portas)
- [Subdomain takeover](#subdomain-takeover)
- [E-mail: SPF e DMARC](#e-mail-spf-e-dmarc)
- [Como o Padmé se comporta na rede](#como-o-padmé-se-comporta-na-rede)

## Como uma mudança vira alerta

```
subdomínios (CT + fontes passivas) ─┐
DNS  A/AAAA/CNAME/MX/NS/SPF/DMARC   ─┤
HTTP status/server/headers          ─┼─► registros ─► diff com o estado ─► eventos ─► canais
TLS  emissor/validade/SANs          ─┤        (SQLite)
takeover (CNAME + assinatura)       ─┤
portas (connect-scan + banner)      ─┘
```

Cada fato observado vira um registro `(tipo, chave, valor)`. A cada varredura o
Padmé compara com o estado anterior:

- chave nova: **added**
- chave que sumiu: **removed**
- mesma chave com valor diferente: **changed** (com o diff por campo, ex.: `status: 200 → 403`)

Regras que evitam alarme falso:

- **Falha de coleta não é remoção.** Se um coletor falhou para um host (timeout,
  fonte fora do ar), aquele escopo não gera `removed`; o estado anterior fica.
- **Primeira varredura é baseline.** Grava o estado sem gerar eventos. Se a
  baseline vier de uma coleta parcial, ela consolida na varredura seguinte.
- **Subdomínio só sai com prova de DNS.** Sumir do CT ou do bruteforce não
  remove; o nome sai quando o próprio DNS dele para de resolver.
- **Rotação de IP vira um evento só.** Registros DNS são agrupados por host e
  tipo (`host|A` = conjunto de IPs).
- **Flapping é amortecido.** Uma chave que oscila muito para de notificar
  (`alerts.flap_threshold`), mas continua no histórico.

A saúde da coleta separa **erro** (um coletor quebrou, a coleta do alvo fica
"parcial") de **inconclusivo** (sem resposta, estado preservado). Os dois
aparecem no painel e no `padme doctor`.

## Severidade

Cada evento recebe uma severidade (`debug`, `low`, `medium`, `high`, `critical`)
e uma confiança (quão certa é a observação), com o motivo em códigos estáveis
(`NEW_OPEN_PORT`, `FORBIDDEN_PORT`, `INTERNET_EXPOSED_ASSET`...).

| Exemplo | Severidade |
|---|---|
| subdomain takeover, porta administrativa ou de banco recém-exposta (RDP, VNC, Redis...) | `critical` |
| porta nova, subdomínio novo, certificado perto de expirar, curinga de DNS, SPF/DMARC fraco | `high` |
| HTTP ou TLS mudou, serviço novo, takeover corrigido | `medium` |
| remoções, mudanças menores, certificado renovado | `low` |
| registros DNS | `debug` |

O contexto do ativo pode elevar a severidade (`context.assets` no config):
`exposure`, `criticality`, `expected_ports` (porta fora da lista vira `high`) e
`forbidden_ports` (vira `critical`).

```yaml
context:
  assets:
    - match: "vpn.exemplo.com"      # nome exato ou glob (*.corp.exemplo.com)
      criticality: critical
      exposure: internet
      forbidden_ports: [22, 3389]
      expected_ports: [443]
```

## Subdomínios

| Fonte | Tipo | Chave | Padrão |
|---|---|---|---|
| `crt.name`, `crt.sh` | Certificate Transparency | não | ligada (`collectors.subdomains`) |
| `certspotter` | Certificate Transparency | não | ligada |
| `otx` | DNS passivo (AlienVault) | opcional | ligada |
| `wayback` | URLs arquivadas | não | ligada |
| `hackertarget` | DNS passivo | não (cota pequena) | desligada |
| `securitytrails` | DNS passivo | sim | desligada |
| `virustotal` | DNS passivo | sim | desligada |
| wordlist | bruteforce de DNS | não | desligado (`collectors.bruteforce`) |

As fontes além do CT (`collectors.passive_sources`):

- só aceitam nomes que **resolvem agora** e não apenas para o curinga de DNS;
- são suplementares: ausência nelas nunca remove nada, e fonte fora do ar não
  deixa a coleta parcial;
- rodam no máximo a cada `passive_every_hours` (padrão 24h), em paralelo, com
  prazo de `passive_timeout` por fonte;
- usam um cliente HTTP próprio, com verificação de TLS, porque levam chave de API.

Chaves vão no `.env` e são mascaradas no log:

```yaml
collectors:
  passive_sources: [certspotter, otx, wayback, securitytrails]
  passive_keys:
    securitytrails: ${PADME_SECURITYTRAILS_KEY}
```

O **curinga de DNS** (`*.alvo.com`) é detectado com nomes aleatórios; sem isso o
bruteforce traria milhares de falsos positivos num apex catch-all. Cada host é
marcado `live` (responde HTTP) ou `quiet`, e o rótulo só muda com prova.

## HTTP, TLS e portas

**HTTP** (um GET por host): status, servidor, destino de redirect, tecnologia
pelos cabeçalhos (nginx, Cloudflare, PHP...) e os **cabeçalhos de segurança que
faltam** (HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy,
Permissions-Policy). Um GET extra em `/favicon.ico` gera um hash para achar
hosts com a mesma stack.

**TLS**: emissor, validade, fingerprint e SANs. Toda reemissão gera `changed`
mostrando quais domínios entraram ou saíram do certificado. A **≤ N dias** do
vencimento (`collectors.cert_expiry_days`, padrão 14) sai um aviso `high`, uma
vez só ao entrar na janela. Com o scan de portas ligado, o certificado também é
lido em portas de TLS implícito abertas (8443, 993, 465, 636...).

**Portas** (`collectors.ports`, **desligado por padrão**): connect-scan na
`ports_list`, com banner-grab leve (SSH, SMTP, FTP...) e versão exata do
MySQL/MariaDB pelo handshake. Mudança de banner = versão de serviço mudou.

## Subdomain takeover

Para cada host com **CNAME**, o alvo é comparado com uma base de serviços
gerada do projeto *can-i-take-over-xyz* (S3, Azure, GitHub Pages, Heroku,
Netlify, Vercel...) e confirmado de um destes jeitos:

- **assinatura**: o corpo HTTP traz a mensagem de recurso não reivindicado
  (ex.: *"There isn't a GitHub Pages site here."*);
- **NXDOMAIN**: em serviços como Azure, o alvo do CNAME não resolve.

CNAME para um serviço fora da base também é checado: se o alvo não resolve **e**
o domínio registrável dele não existe, qualquer um poderia registrá-lo, e o
achado é `critical`. O domínio registrável vem da Public Suffix List; nomes
como `.local`, `.internal` e `.corp` nunca viram achado.

O **RDAP** (`collectors.rdap`) diferencia domínio nunca registrado de expirado:

| RDAP | Significado | Confiança |
|---|---|---|
| 404 | registrável agora | `confirmed` |
| `pendingDelete`, `redemptionPeriod`, `hold` | expirado, vai liberar | `high` |
| registrado e ativo | ninguém reivindica: sem alerta | |
| sem resposta | fica só o sinal do DNS | `high` |

A base de serviços fica em `padme/data/takeover_fingerprints.json`. Um workflow
mensal regenera a base e abre PR quando o upstream muda; o `padme doctor` avisa
se ela passar de 180 dias sem revisão.

## E-mail: SPF e DMARC

O Padmé calcula o **SPF efetivo** seguindo `include:` e `redirect=` (RFC 7208),
como um servidor de e-mail faria para o IP de um atacante. Se um fornecedor
incluído passa a `+all`, sai um evento mesmo sem o seu registro mudar.

| SPF efetivo | Resultado |
|---|---|
| `include:`/`redirect=` para domínio registrável **livre** | `critical`: qualquer um registra o domínio e envia e-mail em seu nome |
| `+all`, `?all`, sem `all`, include que aceita qualquer um, faixa `/8` ou maior | `high` (permissivo) |
| mais de 10 consultas DNS, dois registros SPF, termo inválido | `high` (receptores ignoram o SPF) |
| `~all` ou `-all` | ok |

| DMARC | Resultado |
|---|---|
| `p=none`, `p` ausente ou inválido, dois registros | `high` |
| `sp=none` com `p` rígido | `high` (subdomínios desprotegidos) |
| `pct<100` ou `t=y` com `p=quarantine` | `high` (parte passa sem política) |

> [!IMPORTANT]
> Respostas TXT grandes exigem **TCP/53** até o resolvedor. Se a rede bloquear,
> o SPF desses domínios fica inconclusivo (estado preservado). O `padme doctor`
> testa TCP/53 e aponta isso.

## Como o Padmé se comporta na rede

| Opção | Padrão | O que faz |
|---|---|---|
| `network.follow_redirects` | `false` | Não segue redirects; só registra o destino. Ligado, segue até 5 saltos, cada um validado antes (só `http`/`https` e destino público). |
| `network.allow_private_ips` | `false` | Não sonda HTTP/TLS/portas em hosts que resolvem para IP privado ou reservado (10/8, 192.168/16, 127/8, CGNAT, ULA...). O DNS continua. |
| `network.rate_limit_rps`, `jitter_ms`, `per_host_interval_ms` | desligado | Limita sondas por segundo (global e por host), para não disparar WAF nem rate-limit. |
| `network.max_parallel_connects` | `256` | Teto de conexões simultâneas do scan de portas. |
| `network.max_retries` | `2` | Repete HTTP em `429`/`5xx` com backoff (respeita `Retry-After`); `4xx` nunca repete. |
| `collectors.max_response_bytes` | 256 KiB | Teto do corpo HTTP lido por host. |

> [!NOTE]
> A checagem de IP privado resolve o nome antes de conectar; não é proteção
> completa contra DNS rebinding.

Segredos (token do bot, URL do webhook, chaves de API) nunca aparecem no log,
nem com `-v`: as bibliotecas HTTP são silenciadas e um filtro mascara qualquer
segredo conhecido.
