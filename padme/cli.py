"""CLI do Padmé.

Comandos:
  padme scan     -> roda um scan único e imprime as mudanças (grava baseline)
  padme monitor  -> loop contínuo; alerta no Telegram a cada mudança
  padme events   -> mostra os últimos eventos gravados de um alvo
  padme test-telegram -> envia uma mensagem de teste

Uso responsável: monitore apenas ativos que você é dono ou tem autorização
explícita para testar.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from .alerts import damp_flapping
from .config import Config
from .engine import Engine, build_notifiers, summarize_health
from .levels import Level
from .logredact import install_secret_redaction
from .models import Event
from .notify import TelegramNotifier, send_all
from .scheduler import run_monitor
from .storage import Storage

_LEVEL_CHOICES = [lv.name.lower() for lv in Level]

log = logging.getLogger("padme")


def _print_events(target: str, events: list[Event], baseline: bool) -> None:
    if baseline:
        print(f"[{target}] baseline gravado: {len(events)} itens iniciais.")
        return
    if not events:
        print(f"[{target}] sem mudanças.")
        return
    print(f"[{target}] {len(events)} mudança(s):")
    for e in events:
        arrow = {"added": "+", "removed": "-", "changed": "~"}[e.event_type.value]
        val = e.new_value if e.event_type.value != "removed" else e.old_value
        print(f"  {arrow} [{e.kind.value}] {e.key}  {val or ''}".rstrip())


async def _cmd_scan(cfg: Config, args) -> int:
    if args.level:
        cfg.telegram.level = args.level
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifiers = build_notifiers(cfg) if args.notify else []
    try:
        for target in cfg.targets:
            first = not storage.is_known_target(target)
            t0 = time.monotonic()
            result = await engine.scan_target(target)
            events = engine.apply(result)
            errs = len(result.errors)
            storage.update_health(target, error_count=errs, partial=errs > 0,
                                  duration_ms=int((time.monotonic() - t0) * 1000),
                                  collectors=summarize_health(result))
            _print_events(target, events, baseline=first)
            if errs:
                print(f"[{target}] coleta parcial: {errs} erro(s) de collector "
                      f"(estado preservado; veja -v).")
            for err in result.errors:
                log.debug("erro: %s", err)
            # amortece flapping e cada canal filtra pelo próprio nível; envio concorrente
            if notifiers and not first and events:
                to_notify, flapped = damp_flapping(
                    storage, target, events, cfg.alerts.flap_threshold, cfg.alerts.flap_window_minutes)
                if flapped:
                    print(f"[{target}] {flapped} evento(s) suprimido(s) da notificação (flapping).")
                if to_notify:
                    await send_all(notifiers, target, to_notify)
    finally:
        storage.close()
    return 0


async def _cmd_monitor(cfg: Config, args) -> int:
    if args.interval:
        cfg.interval_seconds = args.interval
    if args.level:
        cfg.telegram.level = args.level
    if args.lock:
        from .singleton import AlreadyRunning, single_instance
        try:
            with single_instance(args.lock):
                await run_monitor(cfg, once=args.once)
        except AlreadyRunning as exc:
            print(f"⏭️  {exc} — pulando esta execução.", file=sys.stderr)
            return 4
    else:
        await run_monitor(cfg, once=args.once)
    return 0


async def _cmd_events(cfg: Config, args) -> int:
    storage = Storage(cfg.db_path)
    try:
        for target in cfg.targets:
            events = storage.recent_events(target, limit=args.limit)
            print(f"=== {target} — últimos {len(events)} eventos ===")
            for e in reversed(events):
                arrow = {"added": "+", "removed": "-", "changed": "~"}[e.event_type.value]
                val = e.new_value if e.event_type.value != "removed" else e.old_value
                print(f"  {arrow} [{e.kind.value}] {e.key}  {val or ''}".rstrip())
    finally:
        storage.close()
    return 0


def _iso(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).isoformat(timespec="seconds")
    except Exception:
        return ""


def _render_export(rows: list[dict], fmt: str, source: str = "") -> str:
    out = [
        {
            "source": source,        # ponto de observação (multi-vantage)
            "target": r["target"],
            "kind": r["kind"],
            "key": r["key"],
            "value": r["value"],
            "first_seen": _iso(r["first_seen"]),
            "last_seen": _iso(r["last_seen"]),
            "metadata": r.get("metadata") or {},
        }
        for r in rows
    ]
    if fmt == "csv":
        buf = io.StringIO()
        cols = ["source", "target", "kind", "key", "value", "first_seen", "last_seen", "metadata"]
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for row in out:  # metadata como JSON string na coluna (CSV é plano)
            w.writerow({**row, "metadata": json.dumps(row["metadata"], ensure_ascii=False)})
        return buf.getvalue()
    return json.dumps(out, indent=2, ensure_ascii=False)


async def _cmd_export(cfg: Config, args) -> int:
    storage = Storage(cfg.db_path)
    try:
        rows = storage.all_state(cfg.targets)
    finally:
        storage.close()
    text = _render_export(rows, args.format, cfg.source)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"{len(rows)} registro(s) exportado(s) [source={cfg.source}] -> {args.out}")
    else:
        print(text)
    return 0


async def _cmd_merge(cfg: Config, args) -> int:
    """Consolida exports de várias fontes (multi-vantage) e mostra divergências."""
    from .merge import merge_exports
    exports: list[list[dict]] = []
    for path in args.files:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Erro lendo {path}: {exc}", file=sys.stderr)
            return 2
        exports.append(data if isinstance(data, list) else data.get("rows", []))
    result = merge_exports(exports)
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"consolidação -> {args.out} "
              f"({result['asset_count']} ativos, {len(result['divergences'])} divergência(s))")
        return 0
    print(f"fontes: {', '.join(result['sources']) or '(nenhuma)'}")
    print(f"ativos: {result['asset_count']} · divergências: {len(result['divergences'])}")
    for a in result["divergences"]:
        if a["divergence"] == "presence":
            print(f"  [presença] [{a['kind']}] {a['key']} — visto de "
                  f"{','.join(a['sources_seen'])}; ausente em {','.join(a['sources_missing'])}")
        else:
            print(f"  [valor]    [{a['kind']}] {a['key']} — valor difere entre fontes")
    return 0


async def _cmd_test_telegram(cfg: Config, args) -> int:
    tg = cfg.telegram
    notifier = TelegramNotifier(tg.bot_token, tg.chat_id)
    if not notifier.configured:
        print("Telegram não configurado (bot_token/chat_id ausentes).")
        return 1
    res = await notifier.send("🛰️ <b>Padmé</b> online. Teste de conexão OK.")
    print("Mensagem enviada." if res.ok else "Falha ao enviar — confira token/chat_id.")
    return 0 if res.ok else 1


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _resolve_web_token(cfg: Config) -> str:
    """Token do painel. Fica FORA do argv (não vira `--token` p/ não vazar em
    `ps`/histórico): vem do YAML (`web.token`, geralmente `${PADME_WEB_TOKEN}`)
    ou direto da env `PADME_WEB_TOKEN`. YAML explícito tem precedência."""
    return (cfg.web.token or os.environ.get("PADME_WEB_TOKEN", "")).strip()


async def _cmd_web(cfg: Config, args) -> int:
    from .webpanel import serve
    host = args.host if args.host is not None else cfg.web.bind
    port = args.port if args.port is not None else cfg.web.port
    token = _resolve_web_token(cfg)
    exposed = host not in _LOOPBACK

    if exposed and not token and not args.allow_no_auth:
        print(
            f"⛔ Recusando servir em {host} (fora de localhost) SEM autenticação.\n"
            "    Isso expõe sua superfície de ataque a qualquer um na rede. Escolha uma:\n"
            "      • defina o token:  export PADME_WEB_TOKEN=... (ou web.token no config)\n"
            "      • sirva local:     padme web            (bind em 127.0.0.1)\n"
            "      • ciente do risco: padme web --host " + host + " --allow-no-auth",
            file=sys.stderr,
        )
        return 3
    if exposed:
        detail = ("protegido por token (Authorization: Bearer)." if token
                  else "SEM autenticação (--allow-no-auth). Só em rede confiável / atrás de proxy.")
        print(f"⚠️  Servindo o painel em {host} (fora de localhost) — {detail}", file=sys.stderr)

    serve(cfg, host, port, exposed=exposed, token=token or None)
    return 0


def _config_warnings(cfg: Config) -> list[str]:
    """Sanidade de configuração (não bloqueia; só diagnostica em `doctor`)."""
    w: list[str] = []
    _PLACEHOLDERS = {"SEU_BOT_TOKEN_AQUI", "SEU_CHAT_ID_AQUI", ""}
    if cfg.interval_seconds <= 0:
        w.append("interval_seconds deve ser > 0")
    if cfg.concurrency <= 0:
        w.append("concurrency deve ser > 0")
    if cfg.timeout <= 0:
        w.append("timeout deve ser > 0")
    if cfg.telegram.enabled and (cfg.telegram.bot_token in _PLACEHOLDERS
                                 or cfg.telegram.chat_id in _PLACEHOLDERS):
        w.append("telegram habilitado mas bot_token/chat_id ausentes ou de exemplo")
    if cfg.discord.enabled and not cfg.discord.webhook_url:
        w.append("discord habilitado mas webhook_url vazio (variável de ambiente definida?)")
    if cfg.webhook.enabled and not cfg.webhook.url:
        w.append("webhook habilitado mas url vazia (variável de ambiente definida?)")
    if cfg.email.enabled and not (cfg.email.smtp_host and cfg.email.from_addr and cfg.email.to):
        w.append("email habilitado mas smtp_host/from/to incompletos")
    return w


async def _cmd_doctor(cfg: Config, args) -> int:
    storage = Storage(cfg.db_path)
    try:
        integ = storage.integrity_check()
        cnt = storage.counts()
        sz = storage.db_size()
        print(f"banco:        {cfg.db_path}")
        print(f"integridade:  {integ}")
        print(f"contagens:    targets={cnt['targets']} state={cnt['state']} events={cnt['events']}")
        print(f"tamanho:      {sz['total'] / 1024:.0f} KiB (db {sz['db'] / 1024:.0f} KiB"
              f" + wal {sz['wal'] / 1024:.0f} KiB)")
        print("alvos:")
        for t in cfg.targets:
            m = storage.target_meta(t) or {}
            base = "sim" if m.get("baseline_initialized") else "não"
            ec = m.get("last_error_count")
            dur = m.get("last_duration_ms")
            print(f"  {t}: baseline={base}"
                  f" · último_scan={_iso(m.get('last_scan_at')) or '—'}"
                  f" · último_ok={_iso(m.get('last_success_at')) or '—'}"
                  f" · erros={ec if ec is not None else '—'}"
                  f" · parcial={'sim' if m.get('last_partial') else 'não'}"
                  f" · dur={dur if dur is not None else '—'}ms")
            ch = m.get("collectors_health") or {}
            if ch:
                bits = " ".join(f"{name}={v.get('status')}" for name, v in sorted(ch.items()))
                print(f"      collectors: {bits}")
        warns = _config_warnings(cfg)
        if warns:
            print("avisos de configuração:")
            for x in warns:
                print(f"  ! {x}")
    finally:
        storage.close()
    return 0 if integ == "ok" else 1


async def _cmd_test_notify(cfg: Config, args) -> int:
    notifiers = build_notifiers(cfg)
    if not notifiers:
        print("Nenhum canal habilitado/configurado (telegram/discord/webhook/email).")
        return 1
    all_ok = True
    for n in notifiers:
        res = await n.announce("teste de conexão OK.")
        all_ok = all_ok and res.ok
        detail = "" if res.ok else f" ({res.error or res.status})"
        print(f"  {getattr(n, 'name', type(n).__name__)}: {'enviado' if res.ok else 'FALHOU'}{detail}")
    return 0 if all_ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="padme",
        description="Padmé — Attack Surface Monitoring com alerta no Telegram.",
    )
    p.add_argument("--version", action="version", version=f"padme {__version__}")
    p.add_argument("-c", "--config", default="config.yaml", help="caminho do config YAML")
    p.add_argument("-v", "--verbose", action="store_true", help="log detalhado")

    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="scan único (grava/atualiza baseline)")
    sp.add_argument("--notify", action="store_true", help="também envia mudanças aos canais de notificação configurados")
    sp.add_argument("--level", choices=_LEVEL_CHOICES, default=None,
                    help="limiar de severidade enviado ao Telegram (sobrescreve o config)")
    sp.set_defaults(func=_cmd_scan)

    mp = sub.add_parser("monitor", help="modo sentinela: varre em loop e alerta no Telegram")
    mp.add_argument("--interval", type=int, default=None, help="sobrescreve interval_seconds")
    mp.add_argument("--level", choices=_LEVEL_CHOICES, default=None,
                    help="limiar de severidade enviado ao Telegram (sobrescreve o config)")
    mp.add_argument("--once", action="store_true",
                    help="roda um único ciclo e sai (ideal p/ cron)")
    mp.add_argument("--lock", default=None, metavar="PATH",
                    help="lock de instância única (flock); sai se já houver uma rodando")
    mp.set_defaults(func=_cmd_monitor)

    ep = sub.add_parser("events", help="lista eventos gravados")
    ep.add_argument("--limit", type=int, default=30)
    ep.set_defaults(func=_cmd_events)

    xp = sub.add_parser("export", help="exporta o estado atual (JSON/CSV)")
    xp.add_argument("--format", choices=["json", "csv"], default="json")
    xp.add_argument("--out", default=None, help="arquivo de saída (padrão: stdout)")
    xp.set_defaults(func=_cmd_export)

    tp = sub.add_parser("test-telegram", help="envia mensagem de teste no Telegram")
    tp.set_defaults(func=_cmd_test_telegram)

    tn = sub.add_parser("test-notify", help="testa TODOS os canais configurados")
    tn.set_defaults(func=_cmd_test_notify)

    wb = sub.add_parser("web", help="painel web read-only do estado/histórico")
    wb.add_argument("--host", default=None, help="bind (padrão: web.bind do config ou 127.0.0.1)")
    wb.add_argument("--port", type=int, default=None, help="porta (padrão: web.port do config ou 8787)")
    wb.add_argument("--allow-no-auth", action="store_true",
                    help="permite servir fora de localhost SEM token (decisão consciente)")
    wb.set_defaults(func=_cmd_web)

    dp = sub.add_parser("doctor", help="diagnóstico: integridade do banco, saúde dos scans e config")
    dp.set_defaults(func=_cmd_doctor)

    mg = sub.add_parser("merge", help="consolida exports de várias fontes (multi-vantage) e mostra divergências")
    mg.add_argument("files", nargs="+", help="arquivos JSON de export (um por fonte/ponto de observação)")
    mg.add_argument("--out", default=None, help="grava a consolidação em JSON (padrão: resumo no stdout)")
    mg.set_defaults(func=_cmd_merge)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if load_dotenv:
        load_dotenv()  # carrega o .env para os ${VAR} do config
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    # nunca vaza token/secret no log (mesmo com -v): sobe httpx p/ WARNING e
    # mascara segredos conhecidos em qualquer mensagem.
    install_secret_redaction()
    try:
        cfg = Config.load(args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Erro de config: {exc}", file=sys.stderr)
        return 2

    # comandos que não varrem alvos não exigem confirmação de escopo
    read_only = args.command in ("events", "export", "test-telegram", "test-notify", "web", "doctor", "merge")
    if not cfg.scope_confirmed and not read_only:
        print(
            "⚠️  scope_confirmed=false no config.\n"
            "    Confirme que você é dono ou tem AUTORIZAÇÃO para monitorar os alvos\n"
            "    e ajuste 'scope_confirmed: true' no config.yaml para prosseguir.",
            file=sys.stderr,
        )
        return 3

    return asyncio.run(args.func(cfg, args))


if __name__ == "__main__":
    raise SystemExit(main())
