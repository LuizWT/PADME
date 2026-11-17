# Changelog

As mudanças de cada versão do Padmé. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e as versões seguem o
[SemVer](https://semver.org/lang/pt-BR/): na série 0.x, *minor* traz recurso ou
mudança de config e *patch* traz correção.

## [Não lançado]

### Adicionado

- Alvos por IP (`203.0.113.7`, `2001:db8::1`) e por faixa (`203.0.113.0/28`),
  com teto de hosts por alvo (`collectors.max_hosts_per_target`, padrão 256).
  Para eles rodam portas, HTTP, TLS e DNS reverso; os nomes descobertos são só
  registrados.

### Corrigido

- Uma faixa em `targets` (`1.2.3.0/24`) virava calada um IP só (`1.2.3.0`), e um
  IP era tratado como domínio (consulta de CT, SPF e DMARC para um número).
- `padme init` com um alvo que o config recusa não deixa mais um arquivo
  inválido para trás.

## [0.2.0] - 2026-11-16

Primeira versão publicada no PyPI (`pip install padme-asm`). A 0.1.0 nunca saiu
como versão; esta reúne tudo o que foi construído até aqui.

### Exige ação para quem usava o código do GitHub

- Python 3.11 ou mais novo. O 3.10 saiu de suporte em outubro de 2026.
- O comando `test-notify` saiu. Para conferir os canais: `padme digest`, que
  mostra `OK` ou `ERRO` em cada um.
- `padme` sem comando agora monitora **e abre o painel**. Para o comportamento
  antigo: `padme --no-web`.
- O config também é procurado na pasta do usuário (`%APPDATA%\padme` ou
  `~/.config/padme`). Um `config.yaml` na pasta atual continua valendo.
- Quem importava `padme.webpanel` passa a importar `padme.web`. O nome antigo
  ainda funciona nesta versão, com aviso.

### Adicionado

- Instaladores de um clique: `install.bat`/`install.ps1` (Windows, também por
  `irm | iex`) e `install.sh` (Linux e macOS). Põem o comando `padme` no PATH.
- `padme init` (config com perguntas), `padme --update` (última versão
  publicada; `--dev` para o último commit do `main`) e `padme -h` com todos os
  comandos e opções, em português.
- Painel web servido junto com o monitor e atualizado em tempo real.
- Ciclo de vida dos problemas: reconhecer, silenciar, aceitar risco, reabrir,
  prazo por severidade e histórico de quem fez o quê.
- Resumo periódico (diário ou semanal) nos canais.
- Fontes de subdomínio além do Certificate Transparency: certspotter,
  AlienVault OTX, Wayback Machine, HackerTarget, SecurityTrails e VirusTotal.
- SPF efetivo (seguindo `include:` e `redirect=`), DMARC, e `include:` de SPF
  apontando para domínio registrável livre.
- RDAP para separar domínio livre de domínio expirado, no takeover e no SPF.
- Canais Telegram, Discord, e-mail e webhook (com assinatura HMAC), cada um com
  seu nível, e fila de reenvio para alertas graves.
- API JSON somente leitura (`padme api`), multi-vantage (`padme merge`),
  `padme backup`, `padme doctor` com sondas de rede e heartbeat.

### Mudado

- README curto; os detalhes técnicos foram para `docs/`.
- O painel foi dividido no pacote `padme.web`, e o mypy entrou no CI.

### Segurança

- `dnspython` 2.9.2, por causa da CVE-2026-114605 e da CVE-2026-128089.

[Não lançado]: https://github.com/LuizWT/PADME/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/LuizWT/PADME/releases/tag/v0.2.0
