<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/LuizWT/PADME/main/docs/assets/padme-logo-dark.png">
    <img src="https://raw.githubusercontent.com/LuizWT/PADME/main/docs/assets/padme-logo-light.png" alt="Padmé — Attack Surface Monitoring Platform" width="560">
  </picture>
</p>

<p align="center">
  <img src="https://github.com/LuizWT/PADME/actions/workflows/tests.yml/badge.svg" alt="tests">
  <img src="https://github.com/LuizWT/PADME/actions/workflows/install.yml/badge.svg" alt="install">
  <a href="https://pypi.org/project/padme-asm/"><img src="https://img.shields.io/pypi/v/padme-asm" alt="PyPI"></a>
</p>

O Padmé vigia a superfície de ataque dos **seus** domínios e avisa quando algo
muda: subdomínio novo, porta aberta, certificado trocado ou perto de vencer,
serviço que subiu ou caiu, versão de serviço com **CVE conhecida**, SPF/DMARC
enfraquecido, possível **subdomain takeover** e, se você ligar, arquivos e
endpoints HTTP públicos por engano. Ele guarda o estado num banco local e só
alerta quando uma varredura encontra diferença em relação à anterior.

Os alertas vão para Telegram, Discord, e-mail ou webhook, e um painel web
mostra tudo em tempo real.

> [!WARNING]
> Monitore **apenas** domínios que são seus ou que você tem autorização
> explícita para testar. A coleta ativa (HTTP, TLS, checagem de exposições e
> principalmente a varredura de portas) toca nos alvos.

## Instalação

### Windows

1. Baixe o projeto ([PADME-main.zip](https://github.com/LuizWT/PADME/archive/refs/heads/main.zip)) e extraia.
2. Dê dois cliques em **`install.bat`**.

Ou, sem baixar nada, cole no PowerShell:

```powershell
irm https://raw.githubusercontent.com/LuizWT/PADME/main/install.ps1 | iex
```

### Linux e macOS

```bash
curl -fsSL https://raw.githubusercontent.com/LuizWT/PADME/main/install.sh | sh
```

Ou, numa pasta clonada: `sh install.sh`.

> [!NOTE]
> Depois de instalar, abra um terminal **novo** para o comando `padme` aparecer.

Outras formas: `pipx install padme-asm` (ou `pip install padme-asm` num ambiente
seu) e [Docker](https://github.com/LuizWT/PADME/blob/main/docs/RUNBOOK.md#2-docker).

## Primeiros passos

```bash
padme init    # domínios, confirmação de autorização e, se quiser, Telegram
padme         # começa a monitorar e abre o painel
```

O painel fica em **http://127.0.0.1:8787**. Deixe o terminal aberto: o Padmé
varre os alvos a cada hora (`interval_seconds`) e para com `Ctrl+C`.

A primeira varredura de cada domínio é a **linha de base**: grava o que existe,
sem alertar. A partir da segunda, cada diferença vira um evento.

## Comandos

| Comando | O que faz |
|---|---|
| `padme` | monitora em loop, alerta nos canais e serve o painel |
| `padme init` | cria o config com algumas perguntas |
| `padme scan` | uma varredura agora, mostrando o que mudou |
| `padme finding list` | problemas abertos (`show`, `ack`, `suppress`, `accept`, `reopen`) |
| `padme digest --print` | resumo do período no terminal (sem `--print`, envia aos canais) |
| `padme events` | histórico de mudanças |
| `padme export` | estado atual em JSON ou CSV |
| `padme doctor` | diagnóstico: banco, saúde das varreduras, config e rede |
| `padme web` | só o painel, sem monitorar |
| `padme api` | API JSON somente leitura (`/api/v1`) |
| `padme backup` | cópia consistente do banco |
| `padme health` | o monitor está varrendo? (código de saída 0 ou 1) |
| `padme merge` | compara exports de várias máquinas |
| `padme --update` | atualiza para a última versão publicada (`--dev`: último commit do main) |

**`padme -h`** lista todos os comandos com todas as opções. As opções do
monitor valem direto no `padme`:

```bash
padme --no-web                # sem o painel
padme --web-port 9000         # painel em outra porta
padme --interval 600          # varre a cada 10 minutos
padme --level high            # canais só recebem high e critical
padme --once                  # uma varredura e sai (para cron ou agendador)
```

## Painel web

- Abre junto com o monitor, em http://127.0.0.1:8787.
- Atualiza **em tempo real**: quando uma varredura grava algo, a página se
  atualiza sozinha, sem perder filtro nem rolagem.
- Mostra os problemas abertos por risco, a atividade dos últimos 30 dias, a
  saúde da coleta e um dossiê por domínio. Dá para reconhecer, silenciar ou
  aceitar um problema por ali.
- Por padrão só aceita conexões desta máquina. Para abrir na rede, defina um
  token: o Padmé se recusa a servir fora de localhost sem um.

Detalhes, problemas (findings) e API: [docs/PAINEL-E-API.md](https://github.com/LuizWT/PADME/blob/main/docs/PAINEL-E-API.md).

## Exposições HTTP

Opcional e **desligada por padrão**. Não tem comando próprio: ligue no config e
ela roda junto com o `padme` e o `padme scan`.

```yaml
collectors:
  exposures: true
  exposures_every_hours: 24   # no máximo uma bateria por host
```

- Faz uma bateria pequena e fixa de GETs sem parâmetros, a partir de uma lista
  curada em `padme/data/exposures.json`. Não é wordlist: não há payloads nem
  varredura de caminhos arbitrários.
- Só roda em host que já respondeu ao coletor HTTP, e no máximo uma vez a cada
  `exposures_every_hours` por host.
- Status `200` sozinho não vira problema: a resposta precisa casar a assinatura
  e o tipo de conteúdo da entrada. Páginas de "não encontrado" disfarçadas,
  redirects para login e páginas de login não contam.
- O conteúdo da resposta **nunca é gravado** (banco, log, painel ou canais): a
  evidência guarda só o caminho, o status, o tipo e o tamanho.
- Severidade: `critical` para segredo ou código, `high` para status ou
  diagnóstico, `medium` para listagem de diretório. O problema traz a correção
  sugerida e some quando um ciclo completo não acha mais a assinatura.
- Valem os mesmos limites da coleta ativa: IP privado, redirects e rate limit.

Detalhes: [docs/DETECCAO.md](https://github.com/LuizWT/PADME/blob/main/docs/DETECCAO.md#exposições-http).

## Alertas

Canais: **Telegram**, **Discord**, **e-mail** (SMTP) e **webhook** JSON (n8n e
automações). Cada canal tem o seu nível mínimo:

| `level` | O canal recebe |
|---|---|
| `critical` | só o crítico: takeover, porta de administração ou banco exposta, CVE crítico, segredo exposto |
| `high` | acima + porta ou subdomínio novo, certificado vencendo, SPF/DMARC fraco, CVE alto |
| `medium` (padrão) | acima + HTTP/TLS mudou, serviço novo, takeover corrigido |
| `low` | acima + remoções e mudanças menores |
| `debug` | tudo, inclusive registros DNS |

O `padme init` configura o Telegram. Para conferir os canais, `padme digest`
manda um resumo agora e mostra `OK` ou `ERRO` em cada um.

Como configurar cada canal, resumo diário/semanal, sinal de vida (heartbeat) e o
formato do webhook: [docs/NOTIFICACOES.md](https://github.com/LuizWT/PADME/blob/main/docs/NOTIFICACOES.md).

## Configuração

O `padme init` cria um config curto. Todas as opções, comentadas, estão em
[`config.example.yaml`](https://github.com/LuizWT/PADME/blob/main/config.example.yaml).

| | Windows | Linux e macOS |
|---|---|---|
| Config | `%APPDATA%\padme\config.yaml` | `~/.config/padme/config.yaml` |
| Segredos (`.env`) e banco (`padme.db`) | na mesma pasta do config | na mesma pasta do config |
| Programa | `%LOCALAPPDATA%\padme` | `~/.local/share/padme` |

O config usado é, nesta ordem: `-c ARQUIVO`, a variável `PADME_CONFIG`, um
`config.yaml` na pasta atual ou o da tabela acima. `padme -h` mostra qual está
em uso.

O mínimo para funcionar:

```yaml
scope_confirmed: true       # você confirma que tem autorização; sem isso nada é varrido
targets:
  - exemplo.com
  - 203.0.113.0/28          # também aceita IP e faixa (até 256 hosts por alvo)
interval_seconds: 3600
collectors:
  ports: false              # varredura de portas: a coleta mais ativa, desligada por padrão
  exposures: false          # checagens HTTP fixas de arquivos/endpoints públicos, desligada por padrão
```

Tokens e senhas ficam no `.env` e entram no YAML como `${VARIAVEL}`:

```dotenv
PADME_TELEGRAM_TOKEN=123456:ABC...
PADME_WEB_TOKEN=um-valor-longo-e-aleatorio
```

## Atualizar e desinstalar

```bash
padme --update            # instala a última versão publicada (PyPI)
padme --update --dev      # instala o último commit do main, antes de virar versão
```

Se o Padmé estiver rodando, reinicie-o depois. Instalado a partir de um clone
(`pip install -e .`), o `--update` faz `git pull`. No Docker, a atualização é
pela imagem. O que mudou em cada versão está no
[CHANGELOG](https://github.com/LuizWT/PADME/blob/main/CHANGELOG.md).

Para desinstalar (config e banco ficam):

| Sistema | Comando |
|---|---|
| Windows | `install.bat -Uninstall`, ou no PowerShell: `$env:PADME_UNINSTALL=1; irm https://raw.githubusercontent.com/LuizWT/PADME/main/install.ps1 \| iex` |
| Linux e macOS | `sh install.sh --uninstall`, ou: `curl -fsSL https://raw.githubusercontent.com/LuizWT/PADME/main/install.sh \| sh -s -- --uninstall` |

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/DETECCAO.md](https://github.com/LuizWT/PADME/blob/main/docs/DETECCAO.md) | o que é coletado, como uma mudança vira alerta, severidade, CVEs (OSV), exposições HTTP, takeover, SPF/DMARC, comportamento na rede |
| [docs/NOTIFICACOES.md](https://github.com/LuizWT/PADME/blob/main/docs/NOTIFICACOES.md) | Telegram, Discord, e-mail, webhook, resumo periódico, heartbeat |
| [docs/PAINEL-E-API.md](https://github.com/LuizWT/PADME/blob/main/docs/PAINEL-E-API.md) | painel, ciclo de vida dos problemas, API JSON, várias máquinas |
| [docs/RUNBOOK.md](https://github.com/LuizWT/PADME/blob/main/docs/RUNBOOK.md) | servidor 24/7: systemd, Docker, backup, rotação de segredos, proxy com TLS |
| [docs/DESENVOLVIMENTO.md](https://github.com/LuizWT/PADME/blob/main/docs/DESENVOLVIMENTO.md) | testes, CI, estrutura do código, release |

## Licença

[MIT](https://github.com/LuizWT/PADME/blob/main/LICENSE)
