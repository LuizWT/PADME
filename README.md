<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/padme-logo-dark.png">
    <img src="docs/assets/padme-logo-light.png" alt="Padmé — Attack Surface Monitoring Platform" width="560">
  </picture>
</p>

<p align="center">
  <img src="https://github.com/LuizWT/PADME/actions/workflows/tests.yml/badge.svg" alt="tests">
  <img src="https://github.com/LuizWT/PADME/actions/workflows/install.yml/badge.svg" alt="install">
</p>

O Padmé vigia a superfície de ataque dos **seus** domínios e avisa quando algo
muda: subdomínio novo, porta aberta, certificado trocado ou perto de vencer,
serviço que subiu ou caiu, SPF/DMARC enfraquecido e possível **subdomain
takeover**. Ele guarda o estado num banco local e só alerta quando uma
varredura encontra diferença em relação à anterior.

Os alertas vão para Telegram, Discord, e-mail ou webhook, e um painel web
mostra tudo em tempo real.

> [!WARNING]
> Monitore **apenas** domínios que são seus ou que você tem autorização
> explícita para testar. A coleta ativa (HTTP, TLS e principalmente a
> varredura de portas) toca nos alvos.

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

### O que o instalador faz

- Procura um Python 3.10 ou mais novo. No Windows, se não houver, oferece
  instalar pelo `winget`.
- Instala o Padmé num ambiente isolado, sem mexer no Python do sistema e sem
  pedir administrador ou `sudo`.
- Cria o comando **`padme`** e o coloca no PATH: nada de `python -m` na frente.
- Roda o `padme init` para criar a configuração.

> [!NOTE]
> Depois de instalar, abra um terminal **novo** para o comando `padme` aparecer.

Outras formas: [Docker](docs/RUNBOOK.md#2-docker) ou
`pipx install https://github.com/LuizWT/PADME/archive/main.zip`.

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
| `padme --update` | atualiza para a versão mais recente do GitHub |

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

Detalhes, problemas (findings) e API: [docs/PAINEL-E-API.md](docs/PAINEL-E-API.md).

## Alertas

Canais: **Telegram**, **Discord**, **e-mail** (SMTP) e **webhook** JSON (n8n e
automações). Cada canal tem o seu nível mínimo:

| `level` | O canal recebe |
|---|---|
| `critical` | só o crítico: takeover, porta de administração ou banco exposta |
| `high` | acima + porta ou subdomínio novo, certificado vencendo, SPF/DMARC fraco |
| `medium` (padrão) | acima + HTTP/TLS mudou, serviço novo, takeover corrigido |
| `low` | acima + remoções e mudanças menores |
| `debug` | tudo, inclusive registros DNS |

O `padme init` configura o Telegram. Para conferir os canais, `padme digest`
manda um resumo agora e mostra `OK` ou `ERRO` em cada um.

Como configurar cada canal, resumo diário/semanal, sinal de vida (heartbeat) e o
formato do webhook: [docs/NOTIFICACOES.md](docs/NOTIFICACOES.md).

## Configuração

O `padme init` cria um config curto. Todas as opções, comentadas, estão em
[`config.example.yaml`](config.example.yaml).

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
interval_seconds: 3600
collectors:
  ports: false              # varredura de portas: a coleta mais ativa, desligada por padrão
```

Tokens e senhas ficam no `.env` e entram no YAML como `${VARIAVEL}`:

```dotenv
PADME_TELEGRAM_TOKEN=123456:ABC...
PADME_WEB_TOKEN=um-valor-longo-e-aleatorio
```

## Atualizar e desinstalar

```bash
padme --update            # baixa e instala a versão mais recente do GitHub
```

Se o Padmé estiver rodando, reinicie-o depois. Instalado a partir de um clone
(`pip install -e .`), o `--update` faz `git pull`. No Docker, a atualização é
pela imagem.

Para desinstalar (config e banco ficam):

| Sistema | Comando |
|---|---|
| Windows | `install.bat -Uninstall`, ou no PowerShell: `$env:PADME_UNINSTALL=1; irm https://raw.githubusercontent.com/LuizWT/PADME/main/install.ps1 \| iex` |
| Linux e macOS | `sh install.sh --uninstall`, ou: `curl -fsSL https://raw.githubusercontent.com/LuizWT/PADME/main/install.sh \| sh -s -- --uninstall` |

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/DETECCAO.md](docs/DETECCAO.md) | o que é coletado, como uma mudança vira alerta, severidade, takeover, SPF/DMARC, comportamento na rede |
| [docs/NOTIFICACOES.md](docs/NOTIFICACOES.md) | Telegram, Discord, e-mail, webhook, resumo periódico, heartbeat |
| [docs/PAINEL-E-API.md](docs/PAINEL-E-API.md) | painel, ciclo de vida dos problemas, API JSON, várias máquinas |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | servidor 24/7: systemd, Docker, backup, rotação de segredos, proxy com TLS |
| [docs/DESENVOLVIMENTO.md](docs/DESENVOLVIMENTO.md) | testes, CI, estrutura do código, release |

## Licença

[MIT](LICENSE)
