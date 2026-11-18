# O que o Padmé detecta e como

[Voltar ao README](../README.md)

- [Como uma mudança vira alerta](#como-uma-mudança-vira-alerta)
- [Severidade](#severidade)
- [Subdomínios](#subdomínios)
- [Exposições HTTP](#exposições-http)
- [HTTP, TLS e portas](#http-tls-e-portas)
- [Versões com CVE conhecida (OSV)](#versões-com-cve-conhecida-osv)
- [Subdomain takeover](#subdomain-takeover)
- [E-mail: SPF e DMARC](#e-mail-spf-e-dmarc)
- [Alvos por IP ou faixa](#alvos-por-ip-ou-faixa)
- [Como o Padmé se comporta na rede](#como-o-padmé-se-comporta-na-rede)

## Como uma mudança vira alerta

```
subdomínios (CT + fontes passivas) ─┐
DNS  A/AAAA/CNAME/MX/NS/SPF/DMARC   ─┤
HTTP status/server/headers          ─┼─► registros ─► diff com o estado ─► eventos ─► canais
exposições HTTP (assinaturas fixas) ─┤
TLS  emissor/validade/SANs          ─┤        (SQLite)
takeover (CNAME + assinatura)       ─┤
portas (connect-scan + banner)      ─┤
CVEs da versão do banner (OSV)      ─┘
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
| versão de serviço com CVE | a do pior CVE (CVSS): `critical`, `high`, `medium` ou `low` |
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

## Exposições HTTP

Com `collectors.exposures: true`, o Padmé faz uma bateria pequena e curada de
GETs sem parâmetros (arquivos de controle de versão, `.env`, páginas de status,
diagnóstico e duas localizações de listagem). A lista fica em
`padme/data/exposures.json`; ela não é uma wordlist e não há payloads ou
varredura de caminhos arbitrários. A bateria só roda para um host que já
respondeu ao coletor HTTP e, por padrão, no máximo a cada 24 horas por host.

Status `200` sozinho nunca gera achado: é obrigatório casar a assinatura de
corpo e o tipo de conteúdo da entrada. Antes da lista há um GET a um caminho
aleatório para reconhecer soft-404; respostas idênticas são ignoradas, salvo
assinaturas explicitamente fortes. Redirects para login e páginas de login não
contam. Cada corpo é limitado a 4 KiB, e os limites de IP privado, redirects,
rate limit global e intervalo por host continuam valendo.

O estado usa `Kind.EXPOSURE` e escopo próprio por host. Um ciclo completo sem
assinatura (inclusive respostas 404) resolve o problema; timeout ou erro deixa
o estado anterior intacto. A evidência contém apenas id da assinatura, caminho,
status, tipo de conteúdo, tamanho e severidade. O conteúdo da resposta nunca é
gravado no banco, logs, painel ou canais de notificação. A severidade base é
`critical` para segredos/código, `high` para status/diagnóstico e `medium` para
listagem de diretório. A correção sugerida aparece no finding.

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

## Versões com CVE conhecida (OSV)

Com o scan de portas ligado, a versão que o banner mostra é consultada no
[OSV](https://osv.dev) (`collectors.osv`, ligado por padrão). O resultado vira
**um problema por porta**, com a lista de CVEs, a severidade do pior e a versão
do pacote que corrige todos:

```
openssh 1:9.2p1-2+deb12u2 · CVE-2024-6387 (high 8.1) · corrige em 1:9.2p1-2+deb12u3
```

Só entra versão de **pacote de distro**, porque é ela que diz o que está
instalado:

| Banner | Pacote consultado | Confiança |
|---|---|---|
| `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` | `openssh` `1:9.2p1-2+deb12u3` no Debian 12 | `high` |
| `MariaDB 10.11.6-0+deb12u1` (handshake) | `mariadb` `1:10.11.6-0+deb12u1` no Debian 12 | `high` |
| `MySQL 8.0.36-0ubuntu0.22.04.1` (handshake) | `mysql-8.0` no Ubuntu 22.04 | `high` |
| `SSH-2.0-OpenSSH_9.2p1 Debian-2` (sem `+debNN`) | a versão do Debian sai da versão upstream | `medium` |
| `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | idem: só o Ubuntu 22.04 traz o 8.9p1 | `medium` |
| `nginx/1.22.1`, `OpenSSH_9.6`, `MariaDB 10.6.12` | não consultado | |

Versão "pelada" não é consultada: a distro corrige falhas sem mudar o número
upstream, então `nginx/1.22.1 (Debian)` pode já estar corrigido, e o OSV
indexa versões por pacote, não por produto. Os produtos e versões de distro
conhecidos estão em `padme/data/osv_products.json` (Debian 10 a 13, Ubuntu
20.04, 22.04 e 24.04).

- **Só CVE com correção publicada** para a sua versão da distro. O que a
  distro não corrigiu (ou marcou como sem importância) aparece só na contagem
  `unfixed` do problema: atualizar não resolveria.
- **Um CVE conta uma vez**, venha do registro da distro (`DEBIAN-CVE-…`,
  `UBUNTU-CVE-…`) ou de um aviso (DSA, DLA, USN). No Ubuntu, um CVE citado só
  num USN não conta: o USN lista os CVEs de todas as versões do aviso, e quem
  diz se ele vale para a sua é o registro `UBUNTU-CVE`. No Debian 11 (LTS) os
  CVEs vêm só dos DLA.
- **Severidade**: a nota do vetor CVSS v3 do registro; sem ela, a do registro
  do próprio CVE; com só CVSS v4, a classificação que o registro traz. Sem
  nenhuma, `medium`.
- **Quando alerta**: CVE novo numa versão em uso (publicado depois, ou versão
  que mudou para uma pior) sai com a severidade do CVE novo. Lista que só
  diminuiu é `low`; versão corrigida ou porta fechada resolve o problema.
- **Sem prova, o CVE fica**: com o OSV fora do ar, com o scan de portas
  inconclusivo ou com a porta aberta mas o banner sem a versão, o problema
  anterior continua. A falha do OSV aparece na saúde da coleta e não deixa a
  coleta do alvo parcial.
- **Uma consulta por varredura**, em lote, só com o que não está no cache
  (24h por pacote e versão, no próprio `padme.db`).
- **Cada CVE tem link para a página dele no OSV**
  (`https://osv.dev/vulnerability/<id>`):
  - no painel, a lista completa no problema e os piores no inventário do
    dossiê;
  - no `padme finding show`;
  - nos alertas, os três que motivaram o aviso (num CVE novo, só o novo);
  - no webhook, a lista completa em `references`.

> [!NOTE]
> A consulta ao OSV leva só ecossistema, pacote e versão
> (`Debian:12`, `openssh`, `1:9.2p1-2+deb12u3`). Nenhum host, IP ou banner sai
> da máquina. Precisa de saída HTTPS para `api.osv.dev`.

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

## Alvos por IP ou faixa

`targets` aceita, além de domínio, um IP (`203.0.113.7`, `2001:db8::1`) ou uma
faixa (`203.0.113.0/28`). Como não há domínio, rodam só os coletores de host:

| Coletor | Domínio | IP ou faixa |
|---|---|---|
| subdomínios, fontes passivas, bruteforce, curinga | sim | não |
| DNS A/AAAA/CNAME/MX, NS, SPF/DMARC, takeover | sim | não |
| DNS reverso (PTR) | não | sim |
| portas e banner | sim | sim |
| HTTP, cabeçalhos, favicon (80/443) | sim | sim |
| exposições HTTP (se ligada) | sim | sim |
| TLS | sim | sim |

- **Teto de hosts.** Uma faixa vira os seus hosts (sem endereço de rede e de
  broadcast no IPv4), até `collectors.max_hosts_per_target` (padrão 256, um
  /24). Faixa maior é recusada ao carregar o config, com a conta na mensagem;
  um /64 de IPv6 nunca é expandido.
- **Forma canônica.** `10.0.0.5/24` (com bits de host) é recusado com a forma
  certa na mensagem (`10.0.0.0/24`), em vez de corrigido calado.
- **Nomes descobertos não entram no escopo.** O PTR e os SANs do certificado de
  um IP ficam registrados, mas só é varrido o que está em `targets`.
- **Rede interna é decisão consciente.** Uma faixa só de endereços privados ou
  reservados com `network.allow_private_ips: false` é erro ao carregar o
  config (antes passaria calada, sem varrer nada).
- **Sem portas, pouca coisa.** Com `collectors.ports: false` (o padrão), um
  alvo IP só é olhado em HTTP e TLS na 443/80. O `padme init` avisa, e o
  `padme doctor` mostra quantas conexões de porta a faixa custa por ciclo.
- As regras de remoção são as mesmas: uma porta só sai do estado quando a
  varredura daquele IP foi observada e não a achou.

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
