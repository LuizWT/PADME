# Ideias — evolução adiada por design

O ROADMAP do PADME foi cumprido: confiabilidade, diff semântico, multi-vantage,
sinais RED, exposure policy, operação 24/7 e as métricas de qualidade (§27) estão
entregues. Este arquivo guarda as evoluções **deliberadamente adiadas** — não por
falta de valor, mas porque cada uma troca a simplicidade arquitetural do projeto
(SQLite, `http.server`, poucas dependências, sem broker/fila/DB central) por
capacidade que só se paga com **necessidade operacional real**.

> [!NOTE]
> Regra de entrada: nenhuma destas ideias entra "porque seria legal". Entra quando
> o problema que ela resolve **aparecer de verdade** em uso. Enquanto não aparece,
> a simplicidade é a feature — deploy trivial, um arquivo de estado, zero serviço
> extra para operar e endurecer.

> [!WARNING]
> Há dependência entre elas. O caminho natural é:
> **lifecycle de finding** → painel deixa de ser 100% read-only (passa a aceitar
> ações) → **RBAC/SSO + auditoria** por usuário → **API programática** de escrita.
> Construir na ordem errada gera retrabalho.

---

## 1. Lifecycle de finding

`finding_id` persistente · acknowledge / suppress / accepted / close · reopen · SLA

### Por quê

Hoje um finding é **derivado a cada scan** de `Event + RiskAssessment` — não tem
identidade estável nem estado próprio. Consequências em uso 24/7 com vários alvos:

- O mesmo problema (ex.: takeover em `blog.x.com`) reaparece a cada ciclo e volta
  a notificar; não há como dizer "isso eu já vi".
- Não dá para **reconhecer** (acknowledge), **silenciar** um falso-positivo já
  avaliado (suppress), **aceitar o risco** (accepted) nem **fechar/reabrir**.
- Sem estado, não há memória operacional nem métrica de tempo-até-resolução (SLA).

O analista repassa o mesmo ruído manualmente — o oposto de "reduzir trabalho do
analista", que é o eixo do projeto.

### Como poderá ser feito

- **`finding_id` determinístico**: hash estável de `(target, kind, key[, campo-chave])`.
  Sobrevive a reemissões — o mesmo problema mantém o mesmo id entre scans.
- **Tabela `findings`** (SQLite, migração via `PRAGMA user_version`, como as atuais):
  `finding_id, target, kind, key, severity, first_seen, last_seen, status,
  status_reason, status_by, status_at, reopen_count`. Status ∈
  `open | acknowledged | suppressed | accepted | closed`.
- **Derivação no `apply_scan`**: ao gerar um `Event`, faz upsert do finding
  correspondente. Se estava `closed` e reaparece → **reopen** (`reopen_count++`,
  volta a `open`). O `state`/`events` continuam como estão (append de observação);
  o `findings` é a camada de *estado de negócio* por cima.
- **Ações**: via CLI (`padme finding ack <id> --reason ...`) e/ou endpoints POST
  no painel sob o mesmo token Bearer. `suppressed`/`accepted` **não notificam**
  (integra com o dispatch de notificação), mas seguem no histórico.
- **SLA**: prazo-alvo por severidade (ex.: `CRITICAL` 24h); o painel mostra
  "aberto há Xh" e marca **SLA estourado**.

### Impacto

- **Ganho**: memória operacional (o que já foi tratado), fim do ruído repetido,
  métricas reais (MTTR, backlog por severidade, taxa de reabertura), loop
  analista→ação fechado.
- **Custo**: primeira **tabela com estado mutável de negócio** (hoje só há
  `state`/`events`); o painel deixa de ser estritamente read-only ao aceitar POST
  (exige cuidado com CSRF/again-token e com o token Bearer); uma migração de schema.
  Mantém **SQLite** — não exige infra nova.
- **Gatilho para construir**: operação recorrente onde o mesmo alerta reaparece e
  alguém precisa dizer "aceito/silencio/já resolvi" — especialmente com mais de um
  analista.

---

## 2. Infra pesada — Postgres / Redis / fila

### Por quê

A escolha atual (SQLite + `http.server` + sem broker) é uma **força**, não uma
limitação: sobe em qualquer lugar, um arquivo de estado, nada de serviço externo
para operar, monitorar e endurecer. Trocar isso só se paga com **escala real**:

- Muitos alvos (dezenas de milhares) e/ou retenção enorme de eventos que o SQLite
  não sirva com latência aceitável.
- **Vários workers concorrentes** escrevendo no mesmo estado (o `flock` de instância
  única e o modelo de um processo deixam de bastar).
- Consultas analíticas pesadas sobre o histórico.
- **Fila** (RabbitMQ / Redis Streams) para desacoplar coleta de processamento num
  fan-out grande.

### Como poderá ser feito

- **Storage plugável**: `storage.py` já isola a persistência. Introduzir um backend
  Postgres implementando a **mesma interface** (padrão Repository), com SQLite como
  default e Postgres opcional (`storage.backend: postgres` + DSN via ambiente).
  Migrações versionadas (Alembic ou SQL por `user_version`).
- **Redis**: cache de estado quente, dedup de flapping e **lock distribuído**
  (substitui o `flock` quando houver multi-host).
- **Fila**: o engine publica um "job de scan" por alvo; workers consomem. O
  `merge.py` já modela multi-vantage **sem DB central** — a fila serviria para
  paralelizar *dentro* de uma vantage, não para centralizar.

### Impacto

- **Ganho**: escala horizontal e concorrência real de coleta/gravação.
- **Custo**: **alto** em complexidade operacional — mais serviços para rodar,
  observar e endurecer; perde-se o "um binário + um arquivo". Aumenta a superfície
  de ataque da própria ferramenta.
- **Gatilho para construir**: SQLite virar **gargalo comprovado** (contenção de
  lock, tamanho, latência de query — medir antes) **ou** necessidade real de
  múltiplos hosts coletando concorrentemente contra o mesmo estado. Sem métrica que
  comprove o gargalo, não entra.

---

## 3. RBAC / SSO / multiusuário

### Por quê

Hoje o painel é **single-tenant**: token Bearer único (ou loopback). Basta para um
operador ou uma equipe pequena e confiável. RBAC/SSO entram quando há:

- **Múltiplos usuários com papéis distintos** (analista só vê; admin configura e age).
- **Auditoria por identidade** — quem reconheceu/silenciou/fechou um finding (casa
  diretamente com o item 1).
- **Integração corporativa** — login via IdP existente.

### Como poderá ser feito

- **Autenticação**: OIDC/SAML contra um IdP (Keycloak / Okta / Azure AD). Introduz
  sessão assinada (cookie) — hoje a auth é *stateless* Bearer.
- **Autorização**: papéis (`viewer` / `analyst` / `admin`) mapeados a permissões
  (ver superfície, exportar, agir em finding, editar config).
- **Auditoria**: log por usuário das ações mutáveis (depende do lifecycle do item 1
  e do painel com POST).
- Provavelmente exige trocar o `http.server` por um framework web mais completo
  (FastAPI/Flask) — o que **puxa dependências** e cruza com o item 4.

### Impacto

- **Ganho**: uso multiusuário/corporativo e auditoria forte por identidade.
- **Custo**: sai do stdlib `http.server`; adiciona **superfície de autenticação**
  (mais a proteger) e estado de sessão.
- **Gatilho para construir**: mais de um usuário com papéis distintos **ou**
  exigência de auditoria/compliance por identidade.

---

## 4. API programática

### Por quê

A saída hoje é painel HTML + `/export` (JSON/CSV) + **webhook** de eventos. Uma API
REST/JSON estável e versionada permitiria:

- Integrar superfície e findings a outras ferramentas — SIEM, ticketing, dashboards
  próprios, automações mais ricas.
- Consultar programaticamente ("findings `CRITICAL` abertos do alvo X").
- Disparar ações de fora (`ack`/`suppress`) — depende do item 1.

### Como poderá ser feito

- A base já existe: `/export` é JSON read-only sob token. Formalizar como **API
  versionada** (`/api/v1/...`): `GET` para `surface`/`events`/`findings` com filtros
  (target, kind, severity, status) e paginação; `POST` para ações de finding.
- **Contrato estável e versionado** (`schema_version`, como o webhook já faz), sob a
  mesma auth Bearer. Documentar via OpenAPI.
- Se crescer, migra do `http.server` para FastAPI (OpenAPI de graça) — cruza com o
  item 3.

### Impacto

- **Ganho**: PADME vira **peça de um pipeline** de segurança, não só um notificador;
  integra com o que o time já usa.
- **Custo**: superfície de API para manter, versionar e endurecer; se expuser
  escrita, herda os cuidados do painel mutável (item 1).
- **Gatilho para construir**: necessidade concreta de **consumir/integrar** o PADME
  a partir de outra ferramenta, ou automações que precisem ler/agir além do push do
  webhook.

---

## Princípio-guia

Cada item acima é bom — e por isso mesmo perigoso: é fácil construir sofisticação
que não reduz trabalho do analista, não aumenta a confiabilidade do estado nem
melhora a clareza da evidência. Enquanto o gatilho real não aparece, **não entra**.
Quando aparecer, seguir a ordem de dependência (1 → 3 → 4; 2 só sob gargalo
comprovado) e o mesmo padrão que trouxe o projeto até aqui: aditivo, testado,
explicável, sem quebrar as invariantes de confiabilidade.
