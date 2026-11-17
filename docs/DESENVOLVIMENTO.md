# Desenvolvimento

[Voltar ao README](../README.md)

## Ambiente

```bash
git clone https://github.com/LuizWT/PADME.git && cd PADME
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt                # versões fixas + pytest, ruff, mypy, pip-audit
pip install -e .                                    # comando `padme` apontando para o código
```

Com `pip install -e .`, o `padme --update` atualiza o clone com `git pull`.

## Checagens

```bash
ruff check padme tests scripts
mypy                                                # tipos (config no pyproject.toml)
pytest -q
pip-audit -r requirements.txt                       # CVEs nas dependências fixas
docker build -t padme:ci . && sh scripts/docker-smoke.sh padme:ci
shellcheck -s sh install.sh
```

O CI (`.github/workflows/`) roda:

| Workflow | Quando | O quê |
|---|---|---|
| `tests` | push, PR e toda segunda | ruff, mypy, pytest em Python 3.11 a 3.15, o pacote (build, `twine check`, instalação limpa), pip-audit, build e smoke test da imagem Docker |
| `install` | push e PR que mexem no instalador ou no pacote | os instaladores de verdade em Ubuntu, macOS e Windows (incluindo o modo `irm \| iex` e a trava de instância única do Windows) |
| `takeover base` | dia 1 de cada mês | regenera a base de takeover e abre PR se o upstream mudou |
| `release` | tag `vX.Y.Z` | publica a versão: PyPI, release do GitHub e imagem no GHCR |

### Tipos

O `mypy` checa o pacote inteiro. Os módulos `padme.web`, `paths`, `updater` e
`initcfg` rodam no modo estrito (toda função anotada, genéricos com tipo); os
outros entram nessa lista do `[tool.mypy]` do `pyproject.toml` aos poucos. Para
conferir os ramos de outro sistema: `mypy --platform win32`.

### Fotos do painel

`tests/test_painel_fotos.py` renderiza as páginas do painel a partir de um banco
fixo, com relógio congelado, e compara byte a byte com `tests/fotos_painel/`.
Uma mudança visual intencional regrava as fotos, e o diff delas vai na PR:

```bash
PADME_REGRAVAR_FOTOS=1 pytest tests/test_painel_fotos.py
```

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

## Versões e release

A versão mora só em `padme/__init__.py` (`__version__`); o `pyproject.toml` lê
de lá. Na série 0.x, *minor* traz recurso ou mudança de config e *patch* traz
correção. Cada versão tem uma seção no [CHANGELOG](../CHANGELOG.md); um teste
falha se `__version__` não tiver a sua.

Para lançar uma versão:

1. Numa PR: suba o `__version__`, renomeie `## [Não lançado]` para
   `## [X.Y.Z] - AAAA-MM-DD` (deixe um `## [Não lançado]` vazio em cima) e
   atualize os links do fim do arquivo.
2. Depois do merge, crie a tag `vX.Y.Z` no `main`, de um destes jeitos:
   - pelo terminal: `git checkout main && git pull && git tag vX.Y.Z && git push origin vX.Y.Z`;
   - pela página do GitHub: *Releases* → *Draft a new release* → em *Choose a
     tag*, digite `vX.Y.Z` e escolha criar a tag no publish, com alvo `main` →
     *Publish release*. **Não precisa escrever notas**: o workflow preenche.
3. O workflow `release` faz o resto: confere tag e changelog, testa, publica no
   TestPyPI e no PyPI, põe as notas do CHANGELOG e os arquivos na release do
   GitHub e publica a imagem em `ghcr.io/luizwt/padme`. Acompanhe em *Actions*
   → *release*; um passo vermelho para o resto sem publicar pela metade.

Se o workflow falhar **antes do PyPI** (nada em pypi.org/project/padme-asm),
corrija numa PR e, depois do merge, recrie a tag no `main` novo: apague a
release (*Releases* → a release → *Delete*) e a tag (*Tags* → `vX.Y.Z` →
*Delete tag*) e crie de novo como no passo 2. O *Re-run* não serve aqui: ele usa
o workflow da tag antiga. Se o PyPI já aceitou a versão, ela não pode ser
publicada de novo, e a correção sai numa versão nova.

Se só o job `docker` falhar (PyPI e release do GitHub já saíram), *Re-run
failed jobs* refaz só a imagem. Na primeira publicação o GHCR pode recusar com
`denied` enquanto cria o pacote; o re-run resolve.

O build sai do workflow, nunca de uma pasta compactada à mão (que levaria
`.env`, `config.yaml` e `padme.db`). Localmente:
`python -m build && twine check --strict dist/*`.

### Configuração única

Feita uma vez, por quem é dono do projeto no PyPI e no GitHub:

1. Contas no [PyPI](https://pypi.org) e no [TestPyPI](https://test.pypi.org).
   São sites e contas separados.
2. Nos **dois**, *Publishing* → *Add a new pending publisher*: projeto
   `padme-asm`, dono `LuizWT`, repositório `PADME`, workflow `release.yml`,
   ambiente `pypi`. Faltando no TestPyPI, a release para no primeiro passo com
   `invalid-publisher`.
3. No GitHub, *Settings* → *Environments* → `pypi` (opcional: exigir aprovação
   antes de publicar).

No GHCR não há nada a configurar nem token a criar: o workflow publica com o
token do próprio Actions. O pacote `padme` nasce na primeira release, ligado ao
repositório pelo label `org.opencontainers.image.source` do `Dockerfile`, e
herda o acesso dele (*Settings* → *Packages* → *Inherit access from source
repository*, ligado por padrão). Com o repositório público, a imagem já nasce
pública.

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
├── web/               painel web (só stdlib)
│   ├── html.py        peças comuns: escape, chips, datas, diff
│   ├── problems.py    painel de problemas e menu de ações
│   ├── overview.py    KPIs, tendência, atividade, saúde dos collectors
│   ├── targets.py     tabela de alvos e dossiê por alvo
│   ├── layout.py      moldura da página
│   ├── pages.py       páginas completas: visão geral, export, multi-vantage
│   ├── auth.py        Bearer, Basic e checagem de origem
│   ├── server.py      servidor HTTP, ações POST e /live em tempo real
│   ├── metrics.py     números dos cartões (sem HTML)
│   └── assets.py      CSS, JS e logo
├── webpanel.py        fachada antiga (reexporta padme.web; sai numa próxima versão)
├── api.py             API JSON /api/v1
├── merge.py           padme merge (multi-vantage)
├── mailpolicy.py      SPF efetivo e DMARC
├── domains.py         domínio registrável (PSL) e RDAP
├── portmap.py         portas: serviço, risco, TLS implícito
├── osv.py             CVEs da versão do banner (OSV): pacote da distro, CVSS, cache
├── netpolicy.py       IP privado/reservado e redirects
├── netcheck.py        sondas de rede do doctor
├── ratelimit.py       ritmo das sondas
├── alerts.py          amortecimento de flapping
├── heartbeat.py       sinal de vida
├── singleton.py       trava de instância única
├── logredact.py       segredos fora dos logs
├── collectors/        subdomains, passive, bruteforce, wildcard, dns, dnsrecon,
│                      http, favicon, exposure, tls, takeover, ports
├── notify/            telegram, discord/webhook, email, formatação, retry
└── data/              base de takeover, produtos do OSV (osv_products.json),
                       exposições HTTP (exposures.json)
install.sh             instalador Linux/macOS
install.ps1            instalador Windows (install.bat chama este)
scripts/               notas do changelog, smoke test da imagem, gerador da base de takeover
docs/                  esta documentação
tests/                 suíte pytest
```

O arquivo [`ideias.md`](../ideias.md) guarda evoluções adiadas de propósito e o porquê.
