# Alertas e notificações

[Voltar ao README](../README.md)

- [Canais](#canais)
- [Nível de cada canal](#nível-de-cada-canal)
- [Entrega garantida dos alertas graves](#entrega-garantida-dos-alertas-graves)
- [Resumo periódico](#resumo-periódico)
- [Sinal de vida (heartbeat)](#sinal-de-vida-heartbeat)
- [Webhook JSON](#webhook-json)

Segredos (tokens, URLs de webhook, senhas) ficam no `.env` ao lado do config e
entram no YAML como `${VARIAVEL}`. O `.env` é lido sozinho.

## Canais

### Telegram

1. No Telegram, fale com `@BotFather`, mande `/newbot` e copie o token.
2. Mande qualquer mensagem para o bot novo e abra
   `https://api.telegram.org/bot<TOKEN>/getUpdates`: o número em `chat.id` é o
   seu chat ID (ou use o `@userinfobot`).
3. O `padme init` pergunta os dois. Para configurar à mão:

```yaml
telegram:
  enabled: true
  bot_token: ${PADME_TELEGRAM_TOKEN}
  chat_id: "123456789"
  level: medium
```

```dotenv
# .env
PADME_TELEGRAM_TOKEN=123456:ABC...
```

### Discord

Configurações do canal, Integrações, Webhooks: crie um e copie a URL.

```yaml
discord:
  enabled: true
  webhook_url: ${PADME_DISCORD_WEBHOOK}
  level: medium
```

### E-mail (SMTP)

SMTP com STARTTLS. No Gmail, use uma *App Password*, não a senha da conta.

```yaml
email:
  enabled: true
  smtp_host: smtp.gmail.com
  smtp_port: 587
  username: ${PADME_SMTP_USER}
  password: ${PADME_SMTP_PASS}
  from: ${PADME_SMTP_USER}
  to: [voce@dominio.com]
  level: high
```

### Webhook (n8n e automações)

Recebe um JSON por varredura com mudança. Formato em [Webhook JSON](#webhook-json).

```yaml
webhook:
  enabled: true
  url: ${PADME_WEBHOOK_URL}
  level: debug
  headers: {X-Token: "${PADME_WEBHOOK_TOKEN}"}   # opcional
  secret: ${PADME_WEBHOOK_SECRET}                # opcional, assina cada envio
```

Todos os canais tentam de novo em timeout, `429` e `5xx` (com backoff e
respeitando `Retry-After`), nunca em outros `4xx`. Os envios são paralelos: um
canal lento ou quebrado não atrasa os outros.

## Nível de cada canal

O terminal mostra tudo. Cada canal recebe só o que estiver no seu `level` ou acima:

| `level` | Recebe |
|---|---|
| `critical` | só subdomain takeover e portas críticas |
| `high` | acima + porta ou subdomínio novo, certificado expirando, curinga de DNS, SPF/DMARC fraco |
| `medium` | acima + HTTP/TLS mudou, serviço novo, takeover corrigido |
| `low` | acima + remoções, mudanças menores, certificado renovado |
| `debug` | tudo, inclusive registros DNS |

Padrão: `medium` em Telegram, Discord e e-mail; `debug` no webhook. O
`padme --level high` vale para todos os canais naquela execução.

## Entrega garantida dos alertas graves

Se um canal falha ao entregar um evento `high` ou `critical` (Telegram fora do
ar, token trocado), o evento entra numa fila no banco e é reenviado **a esse
canal** na varredura seguinte, mesmo depois de reiniciar. Após 5 tentativas ou
24h, o Padmé desiste e registra o erro. O `padme doctor` mostra o que está na fila.

## Resumo periódico

O alerta só fala quando algo muda. Para receber um retrato de tempos em tempos:

```yaml
digest:
  enabled: true
  schedule: daily        # daily | weekly
  hour: 9                # hora local
  weekday: mon           # só no weekly
  channels: []           # vazio = todos
```

Exemplo:

```text
Resumo diário · 2 problema(s) aberto(s)
Período: 25/10 09:00 → 26/10 09:00

3 alvo(s) · 2 problema(s) aberto(s): 1 crítico, 1 alto · 1 com prazo estourado
Mudanças (sem DNS): +5 · ~0 · −0
Coleta: 2 de 3 alvo(s) completos e em dia

acme.com
  abertos: 1 (1 crítico) · prazo estourado: 1
  [crítico] takeover blog.acme.com GitHub Pages
```

- O período é desde o último resumo enviado (fica no banco: reiniciar não
  duplica nem pula). No primeiro uso ele só agenda.
- O resumo ignora o `level` do canal. Se nenhum canal entregar, tenta de novo
  na varredura seguinte.
- Para ver um agora sem enviar: `padme digest --print` (`--hours 168` = semana).

## Sinal de vida (heartbeat)

Um processo morto não avisa que morreu. Com `heartbeat.url` apontando para um
watchdog externo (healthchecks.io, Uptime Kuma, Cronitor), o Padmé faz um GET
a cada varredura; se o sinal parar, o watchdog avisa você. Varredura com falha
chama `url/fail`.

```yaml
heartbeat:
  enabled: true
  url: ${PADME_HEARTBEAT_URL}
```

## Webhook JSON

```json
{
  "schema_version": 1,
  "source": "padme",
  "type": "changes",
  "target": "alvo.com",
  "scan_id": "9f2c…",
  "time": "2026-09-26T00:46:00+00:00",
  "count": 1,
  "events": [
    {"event_id": "a1b2…", "scan_id": "9f2c…",
     "detected_at": "2026-09-26T00:46:00+00:00",
     "severity": "critical", "confidence": "confirmed",
     "risk": {"rule_id": "high-risk-port-added",
              "reasons": ["NEW_OPEN_PORT", "REMOTE_ACCESS_SERVICE", "INTERNET_EXPOSED_ASSET"]},
     "kind": "port", "type": "added", "key": "vpn.alvo.com:3389", "old": null, "new": "open",
     "evidence": {"type": "tcp_connect", "state": "open", "port": 3389},
     "source": "vps-eu", "context": {"exposure": "internet", "criticality": "critical"}}
  ],
  "text": "**PADMÉ** · `alvo.com` ..."
}
```

- `event_id`, `scan_id` e `detected_at` (UTC) servem para deduplicar.
- Em `changed`, o campo `changes` traz o diff por campo.
- O resumo periódico chega com `"type": "digest"`, com `title`, `text` e
  `digest` (os números por alvo).
- O contrato é aditivo: campos novos podem aparecer; `schema_version` só muda
  se algum campo for removido.

### Assinatura

Com `webhook.secret` definido, cada POST leva `X-Padme-Timestamp` (unix) e
`X-Padme-Signature: sha256=<hex>`, o HMAC-SHA256 de `"<timestamp>.<corpo>"`.
Valide sobre os bytes crus do corpo, antes de interpretar o JSON:

```python
import hashlib, hmac, time

def veio_do_padme(secret: bytes, headers, body: bytes, janela=300) -> bool:
    ts = headers["X-Padme-Timestamp"]
    if abs(time.time() - int(ts)) > janela:
        return False                      # reenvio antigo (replay)
    esperado = "sha256=" + hmac.new(secret, ts.encode() + b"." + body,
                                    hashlib.sha256).hexdigest()
    return hmac.compare_digest(esperado, headers["X-Padme-Signature"])
```
