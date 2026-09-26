"""Camada de notificação: Telegram, Discord, webhook genérico (JSON) e e-mail.

Cada notifier tem `name`, `level` (limiar próprio de severidade) e devolve um
`NotificationResult`. `send_all` despacha para todos os canais em paralelo,
cada um aplicando o seu nível.
"""

from .base import (
    NotificationManager,
    NotificationResult,
    Notifier,
    chunk_text,
    post_with_retry,
    send_all,
)
from .email import EmailNotifier, format_events_plain
from .telegram import TelegramNotifier, format_events
from .webhook import DiscordNotifier, WebhookNotifier, format_events_md

__all__ = [
    "TelegramNotifier",
    "DiscordNotifier",
    "WebhookNotifier",
    "EmailNotifier",
    "Notifier",
    "NotificationManager",
    "NotificationResult",
    "send_all",
    "chunk_text",
    "post_with_retry",
    "format_events",
    "format_events_md",
    "format_events_plain",
]
