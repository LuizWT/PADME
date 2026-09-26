"""Carregamento e validação de configuração (YAML)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    level: str = "medium"     # limiar de severidade enviado (ver padme/levels.py)

    def resolved(self) -> "TelegramConfig":
        """Permite usar env vars: bot_token: ${PADME_TG_TOKEN}."""
        return TelegramConfig(
            enabled=self.enabled,
            bot_token=_expand(self.bot_token),
            chat_id=_expand(self.chat_id),
            level=self.level,
        )


@dataclass
class DiscordConfig:
    enabled: bool = False
    webhook_url: str = ""
    level: str = "medium"     # limiar próprio (severidade por canal)

    def resolved(self) -> "DiscordConfig":
        return DiscordConfig(enabled=self.enabled, webhook_url=_expand(self.webhook_url),
                             level=self.level)


@dataclass
class WebhookConfig:
    enabled: bool = False
    url: str = ""
    # webhook é sink de automação (n8n): por padrão recebe o fluxo completo.
    level: str = "debug"
    headers: dict[str, str] = field(default_factory=dict)  # ex.: token de auth

    def resolved(self) -> "WebhookConfig":
        return WebhookConfig(enabled=self.enabled, url=_expand(self.url), level=self.level,
                             headers={k: _expand(str(v)) for k, v in self.headers.items()})


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to: list[str] = field(default_factory=list)
    use_tls: bool = True
    level: str = "medium"     # limiar próprio (severidade por canal)

    def resolved(self) -> "EmailConfig":
        return EmailConfig(
            enabled=self.enabled,
            smtp_host=_expand(self.smtp_host),
            smtp_port=self.smtp_port,
            username=_expand(self.username),
            password=_expand(self.password),
            from_addr=_expand(self.from_addr),
            to=[_expand(t) for t in self.to],
            use_tls=self.use_tls,
            level=self.level,
        )


@dataclass
class NetworkConfig:
    """Política de rede (anti-SSRF / rede interna).

    Padrão SEGURO: não segue redirects e não sonda ativamente IPs
    privados/reservados. Ligue conscientemente para monitorar rede interna.
    """
    allow_private_ips: bool = False
    follow_redirects: bool = False


@dataclass
class StorageConfig:
    """Política de armazenamento. `event_retention_days` = 0 mantém tudo;
    > 0 apaga eventos mais antigos (o `state` nunca é apagado)."""
    event_retention_days: int = 0


@dataclass
class HeartbeatConfig:
    enabled: bool = False
    url: str = ""            # ping de watchdog (healthchecks.io etc.); vazio = só arquivo
    every_cycles: int = 1    # emite o sinal a cada N ciclos
    file: str = ""           # arquivo local com o timestamp da última vida

    def resolved(self) -> "HeartbeatConfig":
        return HeartbeatConfig(
            enabled=self.enabled,
            url=_expand(self.url),
            every_cycles=self.every_cycles,
            file=self.file,
        )


@dataclass
class CollectorsConfig:
    subdomains: bool = True   # passivo (crt.sh / CT logs)
    bruteforce: bool = False  # ativo — resolve candidatos de uma wordlist
    wordlist: str = ""        # caminho da wordlist (vazio = lista embutida)
    wildcard: bool = True     # detecta curinga de DNS e filtra falso-positivo
    wildcard_probes: int = 3  # nomes aleatórios sondados para achar o curinga
    dns: bool = True          # passivo
    http: bool = True         # ativo leve (GET nos hosts)
    tls: bool = True          # ativo leve (handshake)
    cert_expiry_days: int = 14  # avisa quando o cert está a <= N dias de expirar
    max_response_bytes: int = 262144  # teto de corpo HTTP lido por host (256 KiB)
    takeover: bool = True     # CNAME dangling + fingerprint de serviços
    ports: bool = False       # ativo — desligado por padrão
    ports_list: list[int] = field(
        default_factory=lambda: [21, 22, 25, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443]
    )


@dataclass
class Config:
    targets: list[str]
    scope_confirmed: bool = False
    interval_seconds: int = 3600
    concurrency: int = 50
    timeout: float = 8.0
    db_path: str = "padme.db"
    collectors: CollectorsConfig = field(default_factory=CollectorsConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)

    @staticmethod
    def load(path: str | Path) -> "Config":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config não encontrada: {path}")
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        targets = raw.get("targets") or []
        if isinstance(targets, str):
            targets = [targets]
        targets = [t.strip() for t in targets if t and t.strip()]
        if not targets:
            raise ValueError("Config precisa de pelo menos um item em 'targets'.")

        col = raw.get("collectors") or {}
        net = raw.get("network") or {}
        stg = raw.get("storage") or {}
        tg = raw.get("telegram") or {}
        dc = raw.get("discord") or {}
        wh = raw.get("webhook") or {}
        em = raw.get("email") or {}
        hb = raw.get("heartbeat") or {}
        em_to = em.get("to") or []
        if isinstance(em_to, str):
            em_to = [em_to]
        wh_headers = wh.get("headers") or {}
        if not isinstance(wh_headers, dict):
            wh_headers = {}

        return Config(
            targets=targets,
            scope_confirmed=bool(raw.get("scope_confirmed", False)),
            interval_seconds=int(raw.get("interval_seconds", 3600)),
            concurrency=int(raw.get("concurrency", 50)),
            timeout=float(raw.get("timeout", 8.0)),
            db_path=raw.get("db_path", "padme.db"),
            collectors=CollectorsConfig(
                subdomains=bool(col.get("subdomains", True)),
                bruteforce=bool(col.get("bruteforce", False)),
                wordlist=str(col.get("wordlist", "")),
                wildcard=bool(col.get("wildcard", True)),
                wildcard_probes=int(col.get("wildcard_probes", 3)),
                dns=bool(col.get("dns", True)),
                http=bool(col.get("http", True)),
                tls=bool(col.get("tls", True)),
                cert_expiry_days=int(col.get("cert_expiry_days", 14)),
                max_response_bytes=int(col.get("max_response_bytes", 262144)),
                takeover=bool(col.get("takeover", True)),
                ports=bool(col.get("ports", False)),
                ports_list=list(col.get("ports_list", CollectorsConfig().ports_list)),
            ),
            network=NetworkConfig(
                allow_private_ips=bool(net.get("allow_private_ips", False)),
                follow_redirects=bool(net.get("follow_redirects", False)),
            ),
            storage=StorageConfig(
                event_retention_days=int(stg.get("event_retention_days", 0)),
            ),
            telegram=TelegramConfig(
                enabled=bool(tg.get("enabled", False)),
                bot_token=str(tg.get("bot_token", "")),
                chat_id=str(tg.get("chat_id", "")),
                level=str(tg.get("level", "medium")),
            ).resolved(),
            discord=DiscordConfig(
                enabled=bool(dc.get("enabled", False)),
                webhook_url=str(dc.get("webhook_url", "")),
                level=str(dc.get("level", "medium")),
            ).resolved(),
            webhook=WebhookConfig(
                enabled=bool(wh.get("enabled", False)),
                url=str(wh.get("url", "")),
                level=str(wh.get("level", "debug")),
                headers={str(k): str(v) for k, v in wh_headers.items()},
            ).resolved(),
            email=EmailConfig(
                enabled=bool(em.get("enabled", False)),
                smtp_host=str(em.get("smtp_host", "")),
                smtp_port=int(em.get("smtp_port", 587)),
                username=str(em.get("username", "")),
                password=str(em.get("password", "")),
                from_addr=str(em.get("from", "")),
                to=[str(t) for t in em_to],
                use_tls=bool(em.get("use_tls", True)),
                level=str(em.get("level", "medium")),
            ).resolved(),
            heartbeat=HeartbeatConfig(
                enabled=bool(hb.get("enabled", False)),
                url=str(hb.get("url", "")),
                every_cycles=int(hb.get("every_cycles", 1)),
                file=str(hb.get("file", "")),
            ).resolved(),
        )


def _expand(value: str) -> str:
    """Expande ${VAR} usando variáveis de ambiente."""
    if value and value.startswith("${") and value.endswith("}"):
        return os.environ.get(value[2:-1], "")
    return value
