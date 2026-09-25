"""Camada de notificação: Telegram, Discord, webhook genérico (JSON) e e-mail."""

from .email import EmailNotifier, format_events_plain
from .telegram import TelegramNotifier, format_events
from .webhook import DiscordNotifier, WebhookNotifier, format_events_md

__all__ = [
    "TelegramNotifier",
    "DiscordNotifier",
    "WebhookNotifier",
    "EmailNotifier",
    "format_events",
    "format_events_md",
    "format_events_plain",
]
