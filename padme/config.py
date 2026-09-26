"""Carregamento e validação de configuração (YAML)."""

from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_TRUE = {"true", "1", "yes", "y", "on", "sim"}
_FALSE = {"false", "0", "no", "n", "off", "nao", "não", ""}
_VALID_LEVELS = {"debug", "low", "medium", "high", "critical", "all", "verbose", "info",
                 "0", "1", "2", "3", "4"}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _as_bool(v: object, default: bool) -> bool:
    """Booleano robusto: aceita bool nativo ou string ('true'/'false'/'sim'…).
    Evita a armadilha do `bool('false') == True`."""
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    raise ValueError(f"valor booleano inválido: {v!r} (use true/false)")


def _as_int(v: object, name: str, default: int) -> int:
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name}: inteiro inválido: {v!r}") from None


def _as_float(v: object, name: str, default: float) -> float:
    if v is None:
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        raise ValueError(f"{name}: número inválido: {v!r}") from None


def _normalize_target(raw: str) -> str:
    """Normaliza um alvo para APEX canônico. Aceita entradas tolerantes
    (https://x.com/path, X.COM:443, *.x.com, x.com.) e devolve 'x.com'.
    Levanta ValueError se não der pra extrair um domínio válido."""
    t = str(raw).strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split("?", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.count(":") == 1:  # remove :porta (não mexe em IPv6, que tem vários ':')
        t = t.rsplit(":", 1)[0]
    t = t.lstrip("*.").rstrip(".")
    try:  # IDN/punycode: café.com -> xn--caf-dma.com
        t = t.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001 — validação de label decide abaixo
        pass
    labels = t.split(".")
    if not t or len(labels) < 2 or not all(_LABEL_RE.match(lb) for lb in labels):
        raise ValueError(f"alvo inválido: {raw!r} (esperado um domínio apex, ex.: exemplo.com)")
    return t


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
    source: str = ""          # ponto de observação (multi-vantage); vazio = hostname
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
        path = Path(path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Config não encontrada: {path}")
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        # db_path relativo é resolvido em relação ao ARQUIVO DE CONFIG, não ao
        # diretório atual — assim `monitor` e `web` (ambos com -c) sempre abrem o
        # MESMO banco, mesmo rodando de pastas diferentes. Era a causa do painel
        # aparecer vazio: `padme web` de outra pasta abria um padme.db novo.
        db_path = str(raw.get("db_path", "padme.db"))
        if db_path and not Path(db_path).is_absolute():
            db_path = str((path.parent / db_path).resolve())

        raw_targets = raw.get("targets") or []
        if isinstance(raw_targets, str):
            raw_targets = [raw_targets]
        raw_targets = [t for t in raw_targets if t and str(t).strip()]
        if not raw_targets:
            raise ValueError("Config precisa de pelo menos um item em 'targets'.")
        targets: list[str] = []
        for t in raw_targets:  # normaliza e deduplica preservando ordem
            nt = _normalize_target(t)
            if nt not in targets:
                targets.append(nt)

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

        cfg = Config(
            targets=targets,
            scope_confirmed=_as_bool(raw.get("scope_confirmed"), False),
            interval_seconds=_as_int(raw.get("interval_seconds"), "interval_seconds", 3600),
            concurrency=_as_int(raw.get("concurrency"), "concurrency", 50),
            timeout=_as_float(raw.get("timeout"), "timeout", 8.0),
            db_path=db_path,
            source=str(raw.get("source", "")).strip() or socket.gethostname(),
            collectors=CollectorsConfig(
                subdomains=_as_bool(col.get("subdomains"), True),
                bruteforce=_as_bool(col.get("bruteforce"), False),
                wordlist=str(col.get("wordlist", "")),
                wildcard=_as_bool(col.get("wildcard"), True),
                wildcard_probes=_as_int(col.get("wildcard_probes"), "collectors.wildcard_probes", 3),
                dns=_as_bool(col.get("dns"), True),
                http=_as_bool(col.get("http"), True),
                tls=_as_bool(col.get("tls"), True),
                cert_expiry_days=_as_int(col.get("cert_expiry_days"), "collectors.cert_expiry_days", 14),
                max_response_bytes=_as_int(col.get("max_response_bytes"), "collectors.max_response_bytes", 262144),
                takeover=_as_bool(col.get("takeover"), True),
                ports=_as_bool(col.get("ports"), False),
                ports_list=[_as_int(p, "collectors.ports_list", 0)
                            for p in col.get("ports_list", CollectorsConfig().ports_list)],
            ),
            network=NetworkConfig(
                allow_private_ips=_as_bool(net.get("allow_private_ips"), False),
                follow_redirects=_as_bool(net.get("follow_redirects"), False),
            ),
            storage=StorageConfig(
                event_retention_days=_as_int(stg.get("event_retention_days"), "storage.event_retention_days", 0),
            ),
            telegram=TelegramConfig(
                enabled=_as_bool(tg.get("enabled"), False),
                bot_token=str(tg.get("bot_token", "")),
                chat_id=str(tg.get("chat_id", "")),
                level=str(tg.get("level", "medium")),
            ).resolved(),
            discord=DiscordConfig(
                enabled=_as_bool(dc.get("enabled"), False),
                webhook_url=str(dc.get("webhook_url", "")),
                level=str(dc.get("level", "medium")),
            ).resolved(),
            webhook=WebhookConfig(
                enabled=_as_bool(wh.get("enabled"), False),
                url=str(wh.get("url", "")),
                level=str(wh.get("level", "debug")),
                headers={str(k): str(v) for k, v in wh_headers.items()},
            ).resolved(),
            email=EmailConfig(
                enabled=_as_bool(em.get("enabled"), False),
                smtp_host=str(em.get("smtp_host", "")),
                smtp_port=_as_int(em.get("smtp_port"), "email.smtp_port", 587),
                username=str(em.get("username", "")),
                password=str(em.get("password", "")),
                from_addr=str(em.get("from", "")),
                to=[str(t) for t in em_to],
                use_tls=_as_bool(em.get("use_tls"), True),
                level=str(em.get("level", "medium")),
            ).resolved(),
            heartbeat=HeartbeatConfig(
                enabled=_as_bool(hb.get("enabled"), False),
                url=str(hb.get("url", "")),
                every_cycles=_as_int(hb.get("every_cycles"), "heartbeat.every_cycles", 1),
                file=str(hb.get("file", "")),
            ).resolved(),
        )
        _validate(cfg)
        return cfg


def _validate(cfg: "Config") -> None:
    """Falha cedo, com mensagem clara, em config incoerente (§33)."""
    errs: list[str] = []
    if cfg.interval_seconds <= 0:
        errs.append("interval_seconds deve ser > 0")
    if cfg.concurrency <= 0:
        errs.append("concurrency deve ser > 0")
    if cfg.timeout <= 0:
        errs.append("timeout deve ser > 0")
    c = cfg.collectors
    if c.wildcard_probes < 2:
        errs.append("collectors.wildcard_probes deve ser >= 2")
    if c.cert_expiry_days < 0:
        errs.append("collectors.cert_expiry_days deve ser >= 0")
    if c.max_response_bytes <= 0:
        errs.append("collectors.max_response_bytes deve ser > 0")
    for p in c.ports_list:
        if not (1 <= p <= 65535):
            errs.append(f"collectors.ports_list: porta fora de 1..65535: {p}")
    if cfg.storage.event_retention_days < 0:
        errs.append("storage.event_retention_days deve ser >= 0")
    if not (1 <= cfg.email.smtp_port <= 65535):
        errs.append(f"email.smtp_port fora de 1..65535: {cfg.email.smtp_port}")
    for name, lvl in (("telegram", cfg.telegram.level), ("discord", cfg.discord.level),
                      ("webhook", cfg.webhook.level), ("email", cfg.email.level)):
        if str(lvl).strip().lower() not in _VALID_LEVELS:
            errs.append(f"{name}.level inválido: {lvl!r} (use debug/low/medium/high/critical)")
    if errs:
        raise ValueError("Config inválida:\n  - " + "\n  - ".join(errs))


def _expand(value: str) -> str:
    """Expande ${VAR} usando variáveis de ambiente."""
    if value and value.startswith("${") and value.endswith("}"):
        return os.environ.get(value[2:-1], "")
    return value
