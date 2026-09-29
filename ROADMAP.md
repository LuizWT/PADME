# Roadmap do PADME

Rastreador de status da evolução do PADME de um Attack Surface Monitor confiável
para uma ferramenta de **External Attack Surface / Exposure Monitoring** —
mantendo a simplicidade arquitetural (poucas dependências, SQLite, `http.server`,
sem broker/fila/DB central) que é uma das suas forças.

## Eixo de diferenciação

> superfície → estado observado → mudança real → contexto → confiança →
> risco explicável → evidência → ação do analista

A pergunta que o PADME responde cada vez melhor: **"O que mudou na minha
superfície, isso foi observado de forma confiável, por que importa, qual
evidência sustenta a conclusão e o que merece investigação?"**

Regra anti-slop: toda funcionalidade nova precisa reduzir trabalho do analista,
aumentar a confiabilidade do estado, melhorar a clareza da evidência, a segurança
operacional ou a integração. Sofisticação que não faz nada disso não entra.

Legenda: `[x]` feito · `[~]` parcial · `[ ]` pendente · `[-]` adiado por design.

---

## Invariantes de confiabilidade (não regridem)

- [x] Painel `127.0.0.1` por padrão; exposição externa é explícita.
- [x] Erro de coleta nunca vira remoção automática (`CollectionResult.ok`).
- [x] `observed_scopes`: REMOVED só em escopo observado autoritativamente.
- [x] Multi-vantage sem DB central; `merge.py` é a fonte única da consolidação.
- [x] `severity` (impacto) e `confidence` (confiança) são dimensões independentes.
- [x] Regras de risco determinísticas e explicáveis (sem score misterioso).
- [x] Migrações por `PRAGMA user_version` preservam bancos existentes.
- [x] Segredos fora do repositório (`.env`/ambiente); logs mascarados.

---

## V0.2 — Hardening e contexto (P0) — concluído

- [x] Autenticação Bearer opcional do painel (`hmac.compare_digest`).
- [x] `/export` sob a mesma política de token; rota inexistente tratada.
- [x] Headers de segurança (nosniff, X-Frame-Options, Referrer-Policy, no-store, CSP).
- [x] Sanitização do filename do `/export`.
- [x] Reverse proxy + TLS documentados (loopback atrás de Caddy/nginx).
- [x] Contexto de ativo por config (`context.assets`: criticality/environment/exposure).
- [x] `RiskAssessment`: severity + confidence + `rule_id` + reason codes.
- [x] Testes de risco (regras que disparam e que **não** disparam).
- [x] Proveniência mínima (`_collector`/`_source`/`scan_id`/`detected_at`).

## V0.3 — Observabilidade e diff semântico — concluído

- [x] Estado comparável estruturado (`comparable_state`) e diff por campo.
- [x] HTTP semantic diff (status/server/title/location).
- [x] TLS semantic diff (issuer/fingerprint/expires_at) + **SANs**.
- [x] Port diff: banner + **`service`/`product`/`version`** (serviço da porta;
      produto/versão do banner de saudação, mapa curto e explicável).
- [x] Health por collector (`ok`/`partial`/`error` no doctor e no painel).
- [x] Painel mostrando razões/contexto e **evidência normalizada** por evento
      e no **cartão de finding agregado** (topo de "problemas abertos").
- [x] Timeline: eventos por dia + tendência + **priorização por relevância**
      (severidade primeiro, recência depois — o crítico não fica soterrado).

## V0.4 — Multi-vantage + sinais RED — concluído

- [x] `merge` integrado ao painel (`/vantage`), sem DB central.
- [x] Matriz de vantages + divergência de presença/valor.
- [x] Security headers (postura HSTS/CSP/XFO na mesma resposta HTTP).
- [x] Favicon hash (pivot de infraestrutura).
- [x] Tech fingerprint leve (Server/X-Powered-By/…; explicável pelo sinal).
- [x] Sinais RED de DNS no apex (NS + SPF/DMARC) e banner-grab de portas.

## V0.5 — Exposure policy / expected state — concluído

- [x] `expected_ports` (porta fora da lista = UNEXPECTED_PORT).
- [x] `forbidden_ports` (porta proibida aberta = CRITICAL).
- [x] Criticidade e exposição do ativo influenciam a severidade.
- [x] Regras de risco baseadas em contexto.
- [x] Notificações contextualizadas (severity/confidence/reasons por canal).

## Operação 24/7 (§14/§23) — concluído

- [x] `monitor`/`--once`/`--lock` (flock multiplataforma), Docker + Compose.
- [x] systemd documentado com hardening (ProtectSystem=strict, ReadWritePaths…).
- [x] Heartbeat / dead-man's switch (ping externo + arquivo de vida).
- [x] Retenção de eventos; `padme doctor` (integridade + saúde + config).
- [x] **Backup online do SQLite** (`padme backup`, consistente sob WAL).
- [x] Comportamento responsável: **rate-limit** (rps + jitter + intervalo por host)
      e **retry educado** em 429/5xx (respeita `Retry-After`).

## V0.6+ — Lifecycle de finding — adiado até haver necessidade

- [-] `finding_id`/fingerprint persistente, acknowledge, suppress, accepted,
      close/reopen, histórico/SLA. Derivar finding de `Event + RiskAssessment`
      basta até existir uso operacional que justifique estado próprio.

---

## Só com necessidade real (§16/§17/§25) — deliberadamente fora do escopo agora

- [-] Postgres/Redis/RabbitMQ/Neo4j/Elasticsearch, object storage, fila distribuída.
- [-] FastAPI/Flask/Django, SPA/build de frontend.
- [-] RBAC/SSO/OAuth/multiusuário.
- [-] Tabelas `scan_runs`/`assets`/`findings`/`notification_deliveries`.
- [-] Notification outbox persistente; API programática; discovery providers externos.

Cada um entra só quando o problema aparecer de verdade (histórico por execução,
identidade de ativo com relações, lifecycle de finding, entrega durável, etc.).

---

## Próximos incrementos candidatos (baixo risco, mesmo padrão)

- [ ] `service`/`product`/`version` visíveis no painel (hoje vão na evidência/webhook).
- [ ] Mais protocolos no fingerprint de porta conforme aparecerem (sinal claro só).

---

## Métricas de qualidade (§27)

Avaliar evolução por qualidade, não por número de features:

- **False removal rate** — remoções falsas por falha de observação. Meta: 0.
- **Explainability coverage** — % de findings HIGH/CRITICAL com razão + proveniência + evidência.
- **Collector reliability** — success/partial/latency por collector.
- **Alert quality** — alertas relevantes vs. total notificado.
- **Test stability** — pytest + ruff + CI verdes, sem verde artificial.
