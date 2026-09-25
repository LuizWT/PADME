# 🗺️ Roadmap da Padmé

Foco do projeto: **segurança ofensiva (RED)** — recon contínuo de superfície de
ataque em alvos autorizados. Os itens abaixo são polimento de **operação** e
**qualidade de sinal**, não novas categorias de feature.

Legenda de status: ✅ feito · 🔜 planejado · 🏗️ em andamento

---

## 1. Execução resiliente (o sentinela não pode morrer calado) — 🔜

**Problema.** A Padmé roda como 1 processo em 1 máquina. No escopo pessoal, o
"1 máquina" quase não importa — o risco real é **morte silenciosa**: a máquina
dorme, reinicia ou o loop cai, e você **para de receber alertas sem perceber**.
Num recon contínuo, achar que está coberto e não estar é o pior estado.

**Solução.** Nada distribuído. Proporcional ao risco:
- rodar sob supervisor que reinicia sozinho (systemd `Restart=always` ou a
  restart policy do Docker — ver item 4);
- **heartbeat / dead-man's switch**: a Padmé emite sinal de vida a cada N
  ciclos; silêncio = algo quebrou. Opcional: `--once` + cron com lock (flock)
  pra não sobrepor execuções.

**Valor.** Confiabilidade do alerta (critério **d**: não perder evento). No
RED, é não perder o instante em que surge superfície nova no alvo.

**Esforço.** Baixo-médio. Boa parte vem de graça com o item 4 (Docker/systemd).

---

## 2. Qualidade de sinal — subdomínio vivo vs. só um nome em DNS — ✅

**Problema.** Hoje "subdomínio novo" reporta a mera existência em DNS. Um
subdomínio que resolve mas **não sobe serviço** vira ruído: falso-positivo
custa credibilidade (você começa a ignorar os alertas) e, no RED, desperdiça
tempo testando host morto.

**Solução.**
- **Liveness** (implementado nesta fase): classificar cada subdomínio como
  `live` (tem HTTP/TLS/porta viva no mesmo scan) ou `quiet` (só resolve). A
  flag entra no valor do evento, e um `quiet → live` posterior vira um evento
  de mudança — um host dormente que acordou é **alvo novo**.
- **Wildcard DNS** (implementado): o apex é sondado com nomes aleatórios; se
  respondem a tudo (catch-all), a Padmé registra o curinga como evento
  (`WILDCARD`, severidade **high**) e o bruteforce passa a **suprimir** os
  candidatos que só resolvem para os IPs do curinga — um host real resolve para
  um IP diferente e sobrevive ao filtro. Sem isso, a enumeração ativa inundaria
  de subdomínios falsos.

**Valor.** Direto na **qualidade do sinal** (critério **b**). O alerta deixa de
ser "existe um nome" e passa a "existe um **alvo vivo** pra olhar".

**Esforço.** Baixo (liveness) · Médio (wildcard). **Concluído.**

---

## 3. Visão de tendência (a superfície ao longo do tempo) — 🔜

**Problema.** Você vê eventos pontuais (o diff), mas não a foto no tempo. Não
dá pra responder "a superfície do alvo está **crescendo** ou estável?" nem
"quando esse host apareceu pela primeira vez?". Em engajamento longo, tendência
é sinal: pico de hosts novos = deploy = janela.

**Solução.** O dado já existe (`events` + `first_seen`/`last_seen`). Falta só
visualizar no painel: um gráfico simples (hosts/portas por dia) e uma timeline
de eventos. Sem storage novo — query + render.

**Valor.** Transforma histórico morto em **inteligência de alvo**; enxergar o
padrão de quando o alvo mexe na infra.

**Esforço.** Médio, mas barato pelo dado já estar gravado.

---

## 4. Empacotamento (rodar 24/7 num comando) — ✅

**Problema.** Colocar pra rodar em outra máquina é clone + venv + instalar deps
+ configurar serviço na mão — passos que quebram (versão de Python, deps) e
desmotivam. Prejudica reprodutibilidade.

**Solução (implementada).** **Dockerfile** (usuário não-root, config/estado num
volume `/data`, entrypoint `padme`) + **docker-compose.yml** com
`restart: unless-stopped`, então `docker compose up -d` roda o sentinela 24/7
e reinicia sozinho. Para uso local sem Docker, `pipx install .` (ou
`pipx install "git+…"`) — o entrypoint `padme` já vem do `pyproject.toml`.
Falta apenas (opcional) publicar a imagem no GHCR pra `docker pull`.

**Valor.** Reduz "rodar 24/7" a **um comando** — o modo de uso principal
(sentinela) — e resolve metade do item 1 (restart automático vem junto).

**Esforço.** Baixo. **Concluído.**

---

## Itens já concluídos

- ✅ Collectors: subdomains (CT + bruteforce), DNS, HTTP, TLS, **takeover**, portas
- ✅ Diff + histórico em SQLite (WAL)
- ✅ Notificação: Telegram, Discord, webhook JSON, e-mail; níveis de severidade
- ✅ Aviso de expiração de certificado (buckets 14/7/1d)
- ✅ Qualidade de sinal: liveness (live/quiet) + **wildcard DNS** (supressão de falso-positivo)
- ✅ Empacotamento: Dockerfile + docker-compose (restart 24/7) · `pipx install`
- ✅ Export JSON/CSV · painel web read-only · CI (GitHub Actions)
