# Changelog

As mudanças de cada versão do Padmé. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e as versões seguem o
[SemVer](https://semver.org/lang/pt-BR/): na série 0.x, *minor* traz recurso ou
mudança de config e *patch* traz correção.

## [Não lançado]

## [0.3.0] - 2026-11-18

Exposições HTTP, o detalhe de cada CVE com link para o OSV, o Padmé 24/7 no
Windows sem terminal e a imagem Docker também para arm64. Nenhuma opção do
config muda de sentido, e as novas vêm desligadas. Para atualizar:
`padme --update` ou `docker pull ghcr.io/luizwt/padme:0.3.0`.

### Adicionado

- Checagem de exposições HTTP (`collectors.exposures`, desligada por padrão):
  uma bateria pequena e fixa de GETs (lista em `padme/data/exposures.json`),
  no máximo a cada `exposures_every_hours` (padrão 24h) por host que respondeu
  HTTP. Só vira problema quando a assinatura de corpo e o tipo de conteúdo
  casam; o conteúdo da resposta nunca é gravado.
- `padme init --ports` liga a varredura de portas no modo sem perguntas
  (`--target ... --yes`). No modo com perguntas, a pergunta das portas explica
  que são elas que destravam a busca de CVEs, e o fim do init avisa quando a
  busca fica desligada.
- Detalhe dos CVEs de um problema de versão, cada um com link para a página
  no OSV:
  - no painel, a lista completa (com a versão que corrige cada um) e os
    piores no inventário do dossiê;
  - no `padme finding show`;
  - nos alertas do Telegram, Discord e e-mail, os três que motivaram o aviso;
  - no webhook, o campo `references`.
- `padme service install|status|uninstall` (Windows): o Padmé roda 24/7 sem
  terminal, por uma tarefa no Agendador de Tarefas que inicia no logon, roda
  sem janela, reinicia se cair e grava o log em `padme.log`, ao lado do config.
  Não pede administrador.
- `padme monitor --log-file ARQUIVO`: grava o log também num arquivo, que gira
  com 1 MB e guarda 3.
- A imagem Docker (`ghcr.io/luizwt/padme`) sai também para arm64 (Raspberry Pi
  de 64 bits, VPS ARM), na mesma tag. O CI constrói e testa as duas
  arquiteturas.
- Cobertura de testes no CI: o job do Python 3.12 mede linhas e ramos, mostra
  a tabela no resumo da execução, guarda o relatório HTML como artefato e
  falha se o total cair abaixo do piso (`fail_under` no `pyproject.toml`).

## [0.2.0] - 2026-11-17

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
- Alvos por IP (`203.0.113.7`, `2001:db8::1`) e por faixa (`203.0.113.0/28`),
  com teto de hosts por alvo (`collectors.max_hosts_per_target`, padrão 256).
  Para eles rodam portas, HTTP, TLS e DNS reverso; os nomes descobertos são só
  registrados.
- CVEs conhecidos da versão de serviço, pelo [OSV](https://osv.dev)
  (`collectors.osv`, ligado por padrão; precisa de `collectors.ports`). A
  versão de pacote Debian ou Ubuntu lida no banner do SSH e no handshake do
  MySQL/MariaDB vira um problema por porta, com os CVEs que têm correção
  publicada, a severidade do pior (CVSS) e a versão do pacote que corrige
  todos. Só ecossistema, pacote e versão saem da máquina; o resultado fica 24h
  em cache no banco.

### Mudado

- README curto; os detalhes técnicos foram para `docs/`.
- O painel foi dividido no pacote `padme.web`, e o mypy entrou no CI.
- O banner do MySQL/MariaDB mantém a revisão do pacote da distro
  (`MariaDB 10.11.6-0+deb12u1`). Quem já monitorava uma porta dessas recebe um
  evento `low` de banner alterado na primeira varredura.

### Corrigido (em relação ao código do GitHub)

- Uma faixa em `targets` (`1.2.3.0/24`) virava calada um IP só (`1.2.3.0`), e um
  IP era tratado como domínio (consulta de CT, SPF e DMARC para um número).
- `padme init` com um alvo que o config recusa não deixa mais um arquivo
  inválido para trás.

### Segurança

- `dnspython` 2.9.2, por causa da CVE-2026-114605 e da CVE-2026-128089.

[Não lançado]: https://github.com/LuizWT/PADME/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/LuizWT/PADME/releases/tag/v0.3.0
[0.2.0]: https://github.com/LuizWT/PADME/releases/tag/v0.2.0
