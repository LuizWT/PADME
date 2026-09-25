"""Camada de notificação: Telegram, Discord e webhook genérico (JSON)."""

from .email import EmailNotifier, format_events_plain  # noqa: F401
from .telegram import TelegramNotifier, format_events  # noqa: F401
from .webhook import (  # noqa: F401
    DiscordNotifier,
    WebhookNotifier,
    format_events_md,
)
