# Ideias adiadas

[Voltar ao README](../README.md)

Evoluções adiadas **de propósito**. Cada uma troca a simplicidade do Padmé
(SQLite, `http.server`, poucas dependências, nenhum serviço extra) por uma
capacidade que só se paga com necessidade real.

> [!NOTE]
> Nada aqui entra "porque seria legal". Entra quando o problema que resolve
> aparecer em uso. Até lá, a simplicidade é o recurso: instalação trivial, um
> arquivo de estado, nenhum serviço a mais para operar e endurecer.

Já saíram desta lista o ciclo de vida dos problemas (reconhecer, silenciar,
aceitar, reabrir, prazo) e a API JSON somente leitura (`padme api`); estão no
[CHANGELOG](../CHANGELOG.md) e em [PAINEL-E-API.md](PAINEL-E-API.md).

Do que falta, a ordem é **1 → 2**. O item 3 só entra com gargalo medido.

## 1. Vários usuários: papéis e login (RBAC/SSO)

- **Hoje:** um token único, ou só localhost. As ações de problema registram o
  autor, mas não há papéis.
- **Entra quando:** houver mais de um usuário com papéis diferentes, ou
  auditoria por identidade exigida (compliance).
- **Como:** login por um IdP (OIDC ou SAML: Keycloak, Okta, Entra ID) com
  sessão assinada; papéis `viewer`, `analyst` e `admin`; auditoria por usuário.
  Provavelmente exige trocar o `http.server` por FastAPI ou Flask.
- **Custo:** sai da biblioteca padrão e ganha superfície de autenticação e
  estado de sessão.

## 2. API de escrita

- **Hoje:** `/api/v1` só lê (superfície, eventos, saúde, problemas). As ações
  ficam na CLI (`padme finding`) e no painel.
- **Entra quando:** uma ferramenta de fora (SIEM, ticketing, automação) precisar
  agir, e não só ler. Por exemplo, silenciar um problema a partir de um ticket.
- **Como:** `POST` de ação por problema, com a mesma auth, motivo obrigatório e
  registro do autor; contrato versionado e OpenAPI.
- **Custo:** superfície de escrita para manter e endurecer. Depende do item 1
  para saber quem agiu.

## 3. Infra pesada: Postgres, Redis, fila

- **Hoje:** SQLite e um processo por máquina (trava de instância única). Várias
  máquinas se comparam por export (`padme merge`), sem banco central.
- **Entra quando:** o SQLite virar gargalo **medido** (lock, tamanho,
  latência), ou houver vários hosts gravando no mesmo estado.
- **Como:** um backend Postgres atrás da mesma interface do `storage.py` (o
  SQLite continua o padrão), Redis para lock distribuído e cache, e uma fila
  para paralelizar a coleta dentro de uma máquina.
- **Custo:** alto. Mais serviços para rodar, observar e endurecer, e mais
  superfície de ataque na própria ferramenta. Sem métrica que comprove o
  gargalo, não entra.
