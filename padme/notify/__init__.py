"""Camada de notificação: Telegram, Discord e webhook genérico (JSON)."""

from .telegram import TelegramNotifier, format_events  # noqa: F401
from .webhook import (  # noqa: F401
    DiscordNotifier,
    WebhookNotifier,
    format_events_md,
)
