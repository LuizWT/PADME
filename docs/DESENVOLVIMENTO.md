# Desenvolvimento

[Voltar ao README](../README.md)

## Ambiente

```bash
git clone https://github.com/LuizWT/PADME.git && cd PADME
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt                # versões fixas + pytest, ruff, pip-audit
pip install -e .                                    # comando `padme` apontando para o código
```

Com `pip install -e .`, o `padme --update` atualiza o clone com `git pull`.

## Checagens

```bash
ruff check padme tests scripts
pytest -q
pip-audit -r requirements.txt                       # CVEs nas dependências fixas
docker build -t padme:ci . && sh scripts/docker-smoke.sh padme:ci
shellcheck -s sh install.sh
```

O CI (`.github/workflows/`) roda:

| Workflow | Quando | O quê |
|---|---|---|
| `tests` | push, PR e toda segunda | ruff, pytest em Python 3.10 a 3.14, pip-audit, build e smoke test da imagem Docker |
| `install` | push e PR que mexem no instalador ou no pacote | os instaladores de verdade em Ubuntu, macOS e Windows (incluindo o modo `irm \| iex`) |
| `takeover base` | dia 1 de cada mês | regenera a base de takeover e abre PR se o upstream mudou |

## Dependências

- `requirements.txt` é um lock com versões fixas (inclusive transitivas): é o
  que a imagem Docker e o CI instalam.
- `pyproject.toml` tem faixas compatíveis, para quem instala como pacote (os
  instaladores e o `--update` usam este).
- O Dependabot abre PR semanal (Python, GitHub Actions e o digest da imagem
  base). Só faça merge com o CI verde.

## Base de takeover

`padme/data/takeover_fingerprints.json` é gerada do projeto
*can-i-take-over-xyz*:

```bash
python scripts/update_takeover_fingerprints.py --check   # mostra o que mudaria (sai com 3 se mudou)
python scripts/update_takeover_fingerprints.py           # regrava e marca a revisão
pytest -q tests/test_takeover_base.py
```

Entra só o que o upstream marca como *Vulnerable* ou *Edge case* e tem alvo de
CNAME e um sinal (NXDOMAIN ou assinatura no corpo).

## Release

Nunca compacte a pasta à mão (levaria `.env`, `config.yaml` e `padme.db`):

```bash
sh scripts/release.sh            # gera padme-<versão>.tar.gz só com o que está no git
```

## Estrutura

```
padme/
├── __main__.py        entrada do comando `padme` (trata --update antes de carregar o resto)
├── cli.py             comandos e ajuda
├── paths.py           onde ficam config e dados em cada sistema
├── initcfg.py         padme init
├── updater.py         padme --update
├── config.py          leitura e validação do YAML
├── engine.py          roda os coletores e calcula o diff
├── scheduler.py       ciclo de cada alvo (monitor e scan), reenvio, heartbeat
├── differ.py          diff de estado (puro)
├── models.py          Record, Event, CollectionResult
├── risk.py            severidade, confiança e motivos
├── context.py         contexto de ativo (context.assets)
├── evidence.py        evidência normalizada por evento
├── findings.py        ciclo de vida dos problemas e prazos
├── digest.py          resumo periódico
├── storage.py         SQLite: estado, histórico, saúde, migrações
├── webpanel.py        painel web (+ /live em tempo real)
├── panel_metrics.py   números dos cartões do painel
├── panel_assets.py    CSS e JS do painel
├── api.py             API JSON /api/v1
├── merge.py           padme merge (multi-vantage)
├── mailpolicy.py      SPF efetivo e DMARC
├── domains.py         domínio registrável (PSL) e RDAP
├── portmap.py         portas: serviço, risco, TLS implícito
├── netpolicy.py       IP privado/reservado e redirects
├── netcheck.py        sondas de rede do doctor
├── ratelimit.py       ritmo das sondas
├── alerts.py          amortecimento de flapping
├── heartbeat.py       sinal de vida
├── singleton.py       trava de instância única
├── logredact.py       segredos fora dos logs
├── collectors/        subdomains, passive, bruteforce, wildcard, dns, dnsrecon,
│                      http, favicon, tls, takeover, ports
├── notify/            telegram, discord/webhook, email, formatação, retry
└── data/              base de takeover
install.sh             instalador Linux/macOS
install.ps1            instalador Windows (install.bat chama este)
scripts/               release, smoke test da imagem, gerador da base de takeover
docs/                  esta documentação
tests/                 suíte pytest
```

O arquivo [`ideias.md`](../ideias.md) guarda evoluções adiadas de propósito e o porquê.
