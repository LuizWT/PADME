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

O Padmé vigia a superfície de ataque dos **seus** domínios e IPs e avisa quando
algo muda. Ele guarda o estado num banco local e só alerta quando uma varredura
encontra diferença em relação à anterior. Os alertas vão para Telegram,
Discord, e-mail ou webhook, e um painel web mostra tudo em tempo real.

> [!WARNING]
> Monitore **apenas** alvos que são seus ou que você tem autorização explícita
> para testar. A coleta ativa (HTTP, TLS, exposições e principalmente a
> varredura de portas) toca nos alvos.

## Instalação

**Windows:** baixe o [PADME-main.zip](https://github.com/LuizWT/PADME/archive/refs/heads/main.zip),
extraia e dê dois cliques em **`install.bat`**. Ou, sem baixar nada, cole no
PowerShell:

```powershell
irm https://raw.githubusercontent.com/LuizWT/PADME/main/install.ps1 | iex
```

**Linux e macOS:**

```bash
curl -fsSL https://raw.githubusercontent.com/LuizWT/PADME/main/install.sh | sh
```

> [!NOTE]
> Depois de instalar, abra um terminal **novo** para o comando `padme` aparecer.

Outras formas: `pipx install padme-asm` (ou `pip install padme-asm` num ambiente
seu) e [Docker](https://github.com/LuizWT/PADME/blob/main/docs/RUNBOOK.md#2-docker).

## Primeiros passos

```bash
padme init    # alvos, confirmação de autorização e, se quiser, Telegram
padme         # começa a monitorar e abre o painel em http://127.0.0.1:8787
```

Deixe o terminal aberto: o Padmé varre os alvos a cada hora (`interval_seconds`)
e para com `Ctrl+C`. A primeira varredura de cada alvo é a **linha de base**:
grava o que existe, sem alertar. A partir da segunda, cada diferença vira um
evento.

## O que o Padmé detecta

| Detecção | Padrão | Opção no config |
|---|---|---|
| subdomínio novo (Certificate Transparency e fontes passivas) | ligada | `collectors.subdomains` |
| DNS, nameservers, SPF e DMARC fracos | ligada | `collectors.dns`, `collectors.dns_records` |
| HTTP, cabeçalhos de segurança, TLS e certificado vencendo | ligada | `collectors.http`, `collectors.tls` |
| subdomain takeover | ligada | `collectors.takeover` |
| porta aberta e versão do serviço | **desligada** | `collectors.ports` |
| CVE conhecida na versão do serviço ([OSV](https://osv.dev)) | ligada, se `ports` estiver | `collectors.osv` |
| exposições HTTP: arquivos e endpoints públicos por engano | **desligada** | `collectors.exposures` |

`targets` aceita domínio, IP (`203.0.113.7`) e faixa (`203.0.113.0/28`, até 256
hosts). Como cada detecção funciona, a severidade e o que evita alarme falso:
[docs/DETECCAO.md](https://github.com/LuizWT/PADME/blob/main/docs/DETECCAO.md).

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

Abre junto com o monitor e se atualiza **em tempo real**, sem perder filtro nem
rolagem. Mostra os problemas abertos por risco, a atividade dos últimos 30 dias,
a saúde da coleta e um dossiê por alvo, e dá para reconhecer, silenciar ou
aceitar um problema por ali. Por padrão só aceita conexões desta máquina: fora
de localhost, o Padmé exige um token.

Detalhes, problemas (findings) e API: [docs/PAINEL-E-API.md](https://github.com/LuizWT/PADME/blob/main/docs/PAINEL-E-API.md).

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

O `padme init` configura o Telegram, e `padme digest` manda um resumo agora,
mostrando `OK` ou `ERRO` em cada canal. Os outros canais, o resumo
diário/semanal, o sinal de vida (heartbeat) e o formato do webhook:
[docs/NOTIFICACOES.md](https://github.com/LuizWT/PADME/blob/main/docs/NOTIFICACOES.md).

## Configuração

O `padme init` cria um config curto; todas as opções, comentadas, estão no
[`config.example.yaml`](https://github.com/LuizWT/PADME/blob/main/config.example.yaml).
O config usado é, nesta ordem: `-c ARQUIVO`, a variável `PADME_CONFIG`, um
`config.yaml` na pasta atual ou o da tabela abaixo (`padme -h` mostra qual está
em uso).

| | Windows | Linux e macOS |
|---|---|---|
| Config, segredos (`.env`) e banco (`padme.db`) | `%APPDATA%\padme` | `~/.config/padme` |
| Programa | `%LOCALAPPDATA%\padme` | `~/.local/share/padme` |

O mínimo para funcionar:

```yaml
scope_confirmed: true   # você confirma que tem autorização; sem isso nada é varrido
targets:
  - exemplo.com
  - 203.0.113.0/28
```

Tokens e senhas ficam no `.env` e entram no YAML como `${VARIAVEL}`:

```dotenv
PADME_TELEGRAM_TOKEN=123456:ABC...
PADME_WEB_TOKEN=um-valor-longo-e-aleatorio
```

## Atualizar e desinstalar

```bash
padme --update          # última versão publicada (PyPI)
padme --update --dev    # último commit do main, antes de virar versão
```

Se o Padmé estiver rodando, reinicie-o depois. O que mudou em cada versão está
no [CHANGELOG](https://github.com/LuizWT/PADME/blob/main/CHANGELOG.md).

Para desinstalar (config e banco ficam): `install.bat -Uninstall` no Windows ou
`sh install.sh --uninstall` no Linux e macOS. Se instalou pela linha única, rode
a mesma linha com `$env:PADME_UNINSTALL=1;` na frente (PowerShell) ou trocando o
`sh` do fim por `sh -s -- --uninstall` (Linux e macOS).

## Documentação

| Documento | Conteúdo |
|---|---|
| [docs/DETECCAO.md](https://github.com/LuizWT/PADME/blob/main/docs/DETECCAO.md) | cada detecção, como uma mudança vira alerta, severidade, alvos por IP, comportamento na rede |
| [docs/NOTIFICACOES.md](https://github.com/LuizWT/PADME/blob/main/docs/NOTIFICACOES.md) | Telegram, Discord, e-mail, webhook, resumo periódico, heartbeat |
| [docs/PAINEL-E-API.md](https://github.com/LuizWT/PADME/blob/main/docs/PAINEL-E-API.md) | painel, ciclo de vida dos problemas, API JSON, várias máquinas |
| [docs/RUNBOOK.md](https://github.com/LuizWT/PADME/blob/main/docs/RUNBOOK.md) | servidor 24/7: systemd, Docker, backup, rotação de segredos, proxy com TLS |
| [docs/DESENVOLVIMENTO.md](https://github.com/LuizWT/PADME/blob/main/docs/DESENVOLVIMENTO.md) | testes, CI, estrutura do código, release |
| [docs/IDEIAS.md](https://github.com/LuizWT/PADME/blob/main/docs/IDEIAS.md) | evoluções adiadas de propósito e quando entram |

## Licença

[MIT](https://github.com/LuizWT/PADME/blob/main/LICENSE)
