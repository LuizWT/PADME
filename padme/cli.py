"""CLI do Padmé. `padme -h` lista todos os comandos e opções.

Sem comando, `padme` roda o monitor com o painel web junto (um terminal só).
Comandos: monitor, init, web, scan, finding, digest, events, export, doctor,
health, backup, api, merge. Opções gerais: -c/--config, -v, --update, --version.

Uso responsável: monitore apenas ativos que você é dono ou tem autorização
explícita para testar.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import getpass
import io
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

from . import __version__, netcheck
from .config import Config
from .engine import Engine, build_notifiers
from .findings import ACTIONS, ACTIVE, STATUS_LABEL, STATUSES, human_hours, sla_info
from .logredact import install_secret_redaction
from .models import Event
from .paths import find_config
from .risk import Level
from .scheduler import run_monitor
from .storage import Storage, StorageOutdated

_LEVEL_CHOICES = [lv.name.lower() for lv in Level]

log = logging.getLogger("padme")


def _print_events(target: str, events: list[Event], baseline: bool,
                  total: int = 0, provisional: bool = False) -> None:
    if baseline:
        if provisional:
            print(f"[{target}] baseline PROVISÓRIA: {total} itens (coleta incompleta; "
                  "consolida no próximo scan, sem gerar eventos).")
        else:
            print(f"[{target}] baseline gravado: {total} itens iniciais.")
        return
    if not events:
        print(f"[{target}] sem mudanças.")
        return
    print(f"[{target}] {len(events)} mudança(s):")
    for e in events:
        arrow = {"added": "+", "removed": "-", "changed": "~"}[e.event_type.value]
        val = e.new_value if e.event_type.value != "removed" else e.old_value
        print(f"  {arrow} [{e.kind.value}] {e.key}  {val or ''}".rstrip())


def _override_levels(cfg: Config, level: str | None) -> None:
    """`--level` vale para TODOS os canais (antes só mexia no Telegram)."""
    if level:
        for channel in (cfg.telegram, cfg.discord, cfg.webhook, cfg.email):
            channel.level = level


async def _cmd_scan(cfg: Config, args) -> int:
    """Um ciclo avulso, pelo MESMO caminho do monitor (scheduler.scan_one), só
    que imprimindo as mudanças. Com --notify, notifica e usa a fila de reenvio."""
    from .notify import NotificationManager
    from .scheduler import retry_pending, scan_one

    _override_levels(cfg, args.level)
    storage = Storage(cfg.db_path)
    engine = Engine(cfg, storage)
    notifier = NotificationManager(build_notifiers(cfg) if args.notify else [])
    try:
        if notifier:
            await retry_pending(storage, notifier)
        for target in cfg.targets:
            o = await scan_one(cfg, engine, storage, notifier, target)
            _print_events(target, o.events, baseline=o.first, total=len(o.result.records),
                          provisional=o.provisional)
            if o.result.errors:
                print(f"[{target}] coleta parcial: {len(o.result.errors)} erro(s) de collector "
                      f"(estado preservado; veja -v).")
            for err in o.result.errors:
                log.debug("erro: %s", err)
            if o.flapped:
                print(f"[{target}] {o.flapped} evento(s) suprimido(s) da notificação (flapping).")
            if o.muted:
                print(f"[{target}] {o.muted} evento(s) de finding(s) silenciado(s)/aceito(s) "
                      "não notificado(s).")
            if o.failed_channels:
                print(f"[{target}] notificação falhou em: {', '.join(o.failed_channels)}"
                      + (f" ({o.queued} alerta(s) grave(s) na fila de reenvio)" if o.queued else ""))
    finally:
        storage.close()
    return 0


def _start_panel(cfg: Config, args) -> None:
    """Painel web numa thread do próprio monitor: um terminal só. Se não der
    para abrir (porta ocupada, exposto sem token), avisa e o monitor segue."""
    from .web.server import start_background
    target = _panel_target(cfg, args.web_host, args.web_port, args.allow_no_auth)
    if isinstance(target, str):
        print(target + "\n  O monitor segue sem o painel.", file=sys.stderr)
        return
    host, port, token, exposed = target
    try:
        start_background(cfg, host, port, exposed=exposed, token=token or None)
    except OSError as exc:
        print(f"AVISO: o painel não abriu em {host}:{port} ({exc.strerror or exc}). "
              "O monitor segue sem ele; mude web.port no config ou use --web-port.",
              file=sys.stderr)
        return
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"Painel: http://{shown}:{port}" + (" (com token)" if token else ""), flush=True)


async def _cmd_monitor(cfg: Config, args) -> int:
    if args.interval:
        cfg.interval_seconds = args.interval
    _override_levels(cfg, args.level)
    if not args.once and not args.no_web:
        await asyncio.to_thread(_start_panel, cfg, args)
    if args.lock:
        from .singleton import AlreadyRunning, single_instance
        try:
            with single_instance(args.lock):
                await run_monitor(cfg, once=args.once)
        except AlreadyRunning as exc:
            print(f"{exc} — pulando esta execução.", file=sys.stderr)
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


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _resolve_web_token(cfg: Config) -> str:
    """Token do painel. Fica FORA do argv (não vira `--token` p/ não vazar em
    `ps`/histórico): vem do YAML (`web.token`, geralmente `${PADME_WEB_TOKEN}`)
    ou direto da env `PADME_WEB_TOKEN`. YAML explícito tem precedência."""
    return (cfg.web.token or os.environ.get("PADME_WEB_TOKEN", "")).strip()


def _panel_target(cfg: Config, host: str | None, port: int | None,
                  allow_no_auth: bool) -> tuple[str, int, str, bool] | str:
    """(host, porta, token, exposto) do painel, ou a mensagem de recusa: fora
    de localhost SEM token o painel expõe sua superfície de ataque à rede."""
    host = host if host is not None else cfg.web.bind
    port = port if port is not None else cfg.web.port
    token = _resolve_web_token(cfg)
    exposed = host not in _LOOPBACK
    if exposed and not token and not allow_no_auth:
        return (f"Recusando abrir o painel em {host} (fora de localhost) SEM autenticação:\n"
                "  qualquer um na rede veria sua superfície de ataque. Escolha uma:\n"
                "    - defina o token: PADME_WEB_TOKEN no .env (ou web.token no config)\n"
                "    - use só nesta máquina: web.bind: 127.0.0.1 (padrão)\n"
                "    - ciente do risco: --allow-no-auth")
    if exposed:
        detail = ("protegido por token." if token
                  else "SEM autenticação (--allow-no-auth). Só em rede confiável.")
        print(f"AVISO: painel em {host} (fora de localhost) — {detail}", file=sys.stderr)
    return host, port, token, exposed


async def _cmd_web(cfg: Config, args) -> int:
    from .web.server import serve
    target = _panel_target(cfg, args.host, args.port, args.allow_no_auth)
    if isinstance(target, str):
        print(target, file=sys.stderr)
        return 3
    host, port, token, exposed = target
    serve(cfg, host, port, exposed=exposed, token=token or None)
    return 0


def _resolve_api_token(cfg: Config) -> str:
    """Token da API: `api.token`/`PADME_API_TOKEN` e, se vazio, cai no token do
    painel (`web.token`/`PADME_WEB_TOKEN`) — a mesma auth Bearer."""
    return ((cfg.api.token or os.environ.get("PADME_API_TOKEN", "")).strip()
            or _resolve_web_token(cfg))


async def _cmd_api(cfg: Config, args) -> int:
    from .api import serve
    host = args.host if args.host is not None else cfg.api.bind
    port = args.port if args.port is not None else cfg.api.port
    token = _resolve_api_token(cfg)
    exposed = host not in _LOOPBACK

    if exposed and not token and not args.allow_no_auth:
        print(
            f"⛔ Recusando servir a API em {host} (fora de localhost) SEM autenticação.\n"
            "    A API expõe toda a superfície coletada. Escolha uma:\n"
            "      • defina o token:  export PADME_API_TOKEN=... (ou api.token no config)\n"
            "      • sirva local:     padme api            (bind em 127.0.0.1)\n"
            "      • ciente do risco: padme api --host " + host + " --allow-no-auth",
            file=sys.stderr,
        )
        return 3
    if exposed:
        detail = ("protegida por token (Authorization: Bearer)." if token
                  else "SEM autenticação (--allow-no-auth). Só em rede confiável / atrás de proxy.")
        print(f"⚠️  Servindo a API em {host} (fora de localhost) — {detail}", file=sys.stderr)

    serve(cfg, host, port, token=token or None)
    return 0


def _config_warnings(cfg: Config) -> list[str]:
    """Sanidade de configuração (não bloqueia; só diagnostica em `doctor`)."""
    w: list[str] = list(cfg.warnings)
    # (limites numéricos já são garantidos por config._validate no carregamento)
    _PLACEHOLDERS = {"SEU_BOT_TOKEN_AQUI", "SEU_CHAT_ID_AQUI", ""}
    if cfg.telegram.enabled and (cfg.telegram.bot_token in _PLACEHOLDERS
                                 or cfg.telegram.chat_id in _PLACEHOLDERS):
        w.append("telegram habilitado mas bot_token/chat_id ausentes ou de exemplo")
    if cfg.discord.enabled and not cfg.discord.webhook_url:
        w.append("discord habilitado mas webhook_url vazio (variável de ambiente definida?)")
    if cfg.webhook.enabled and not cfg.webhook.url:
        w.append("webhook habilitado mas url vazia (variável de ambiente definida?)")
    if cfg.email.enabled and not (cfg.email.smtp_host and cfg.email.from_addr and cfg.email.to):
        w.append("email habilitado mas smtp_host/from/to incompletos")
    if cfg.collectors.takeover:
        stale = _fingerprints_stale_days()
        if stale:
            w.append(f"base de fingerprints de takeover sem revisão há {stale} dias "
                     "(padme/data/takeover_fingerprints.json — compare com can-i-take-over-xyz)")
    return w


def _fingerprints_stale_days(max_days: int = 180) -> int:
    """Dias desde a última revisão da base de takeover, se passou de `max_days`."""
    from .collectors.takeover import FINGERPRINTS_REVIEWED
    try:
        days = (datetime.now() - datetime.fromisoformat(FINGERPRINTS_REVIEWED)).days
    except ValueError:
        return max_days + 1  # sem data válida = nunca revisada
    return days if days > max_days else 0


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
                  f" · inconclusivos={m.get('last_inconclusive') or 0}"
                  f" · parcial={'sim' if m.get('last_partial') else 'não'}"
                  f" · dur={dur if dur is not None else '—'}ms")
            ch = m.get("collectors_health") or {}
            if ch:
                bits = " ".join(f"{name}={v.get('status')}" for name, v in sorted(ch.items()))
                print(f"      collectors: {bits}")
        pend = storage.pending_counts()
        if pend:
            bits = " ".join(f"{ch}={n}" for ch, n in sorted(pend.items()))
            print(f"alertas graves aguardando reenvio: {bits}")
        warns = _config_warnings(cfg)
        if warns:
            print("avisos de configuração:")
            for x in warns:
                print(f"  ! {x}")
        # sondas de rede (best-effort; não mudam o código de saída): TCP/53 e
        # HTTPS de saída, as duas vias que o firewall costuma bloquear e que
        # deixam a coleta inconclusiva sem erro visível.
        net = await netcheck.run(cfg, timeout=min(cfg.timeout, 5.0))
        if net:
            print("rede:")
            for line in net:
                print(line)
    finally:
        storage.close()
    return 0 if integ == "ok" else 1


async def _cmd_backup(cfg: Config, args) -> int:
    out = args.out or f"padme-backup-{datetime.now():%Y%m%d-%H%M%S}.db"
    storage = Storage(cfg.db_path)
    try:
        res = storage.backup(out)
    finally:
        storage.close()
    print(f"backup:       {res['path']}")
    print(f"tamanho:      {res['bytes'] / 1024:.0f} KiB")
    print(f"integridade:  {res['integrity']}")
    if res["integrity"] != "ok":
        print("! integridade do backup não confirmada — verifique o destino.", file=sys.stderr)
        return 1
    return 0


async def _cmd_health(cfg: Config, args) -> int:
    """Liveness do sentinela, SEM rede e sem escrita: o último scan de algum alvo
    é recente? Serve de HEALTHCHECK do Docker / check de cron. Exit 0 = saudável,
    1 = parado/atrasado/sem banco. Coleta parcial NÃO derruba (isso é o doctor)."""
    max_age = args.max_age if args.max_age is not None else 2 * cfg.interval_seconds + 600
    try:
        storage = Storage(cfg.db_path, readonly=True)
    except (FileNotFoundError, StorageOutdated) as exc:
        print(f"unhealthy: {exc}")
        return 1
    try:
        last = [float(m["last_scan_at"]) for t in cfg.targets
                if (m := storage.target_meta(t)) and m.get("last_scan_at")]
    finally:
        storage.close()
    if not last:
        print("unhealthy: nenhum scan registrado ainda")
        return 1
    age = datetime.now().timestamp() - max(last)
    if age > max_age:
        print(f"unhealthy: último scan há {int(age)}s (limite {max_age}s)")
        return 1
    print(f"healthy: último scan há {int(age)}s")
    return 0


def _actor(args) -> str:
    """Quem fez a ação (trilha de auditoria): --by, ou o usuário do SO."""
    if getattr(args, "by", None):
        return args.by
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — sem usuário resolvível (container sem passwd)
        return "cli"


def _sla_text(row: dict, sla_hours: dict) -> str:
    info = sla_info(row, time.time(), sla_hours)
    if not info or not info["limit_h"]:
        return "—"
    if info["breached"]:
        return f"estourado há {human_hours(info['left_h'])}"
    return f"vence em {human_hours(info['left_h'])}"


async def _cmd_finding(cfg: Config, args) -> int:
    storage = Storage(cfg.db_path)
    try:
        if args.action == "list":
            if args.all:
                rows = storage.list_findings(target=args.target, status=args.status)
            elif args.status:
                rows = storage.list_findings(target=args.target, status=args.status)
            else:  # padrão: só o que pede ação
                rows = [r for r in storage.list_findings(target=args.target)
                        if r["status"] in ACTIVE]
            if not rows:
                print("nenhum finding" + (" com esse filtro." if (args.status or args.target)
                                           else " ativo. (--all mostra tratados e resolvidos)"))
                return 0
            print(f"{'ID':<10}  {'ESTADO':<12}  {'SEV':<8}  {'IDADE':>6}  {'PRAZO':<18}  "
                  f"{'ALVO':<20}  PROBLEMA")
            now = time.time()
            for r in rows:
                age = human_hours((now - r["opened_at"]) / 3600)
                print(f"{r['finding_id'][:10]:<10}  {STATUS_LABEL.get(r['status'], r['status']):<12}  "
                      f"{r['severity']:<8}  {age:>6}  {_sla_text(r, cfg.findings.sla_hours):<18}  "
                      f"{r['target']:<20}  {r['title']}")
            return 0
        if not args.id:
            print(f"informe o id do finding: padme finding {args.action} <id>", file=sys.stderr)
            return 2
        try:
            if args.action == "show":
                row = storage.get_finding(args.id)
                if row is None:
                    raise ValueError(f"finding não encontrado: {args.id}")
                print(f"{row['finding_id']}  [{STATUS_LABEL.get(row['status'], row['status'])}]  "
                      f"{row['severity']}")
                print(f"  {row['title']}")
                print(f"  alvo: {row['target']} · kind: {row['kind']} · key: {row['key']}")
                print(f"  visto: {_iso(row['first_seen'])} → {_iso(row['last_seen'])}"
                      f"{'' if row['present'] else ' (ausente no estado atual)'}"
                      f" · reaberto {row['reopen_count']}x · prazo: "
                      f"{_sla_text(row, cfg.findings.sla_hours)}")
                print("  histórico:")
                for h in storage.finding_history(row["finding_id"]):
                    frm = STATUS_LABEL.get(h["from_status"], h["from_status"] or "—")
                    print(f"    {_iso(h['ts'])}  {frm} → {STATUS_LABEL.get(h['to_status'], h['to_status'])}"
                          f"  por {h['actor'] or '?'}" + (f": {h['reason']}" if h["reason"] else ""))
                return 0
            row = storage.set_finding_status(args.id, args.action, reason=args.reason or "",
                                             actor=_actor(args))
        except ValueError as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 1
        print(f"{row['finding_id'][:10]} → {STATUS_LABEL.get(row['status'], row['status'])}: "
              f"{row['title']}")
        return 0
    finally:
        storage.close()


async def _cmd_digest(cfg: Config, args) -> int:
    """Resumo do período agora: `--print` só mostra; sem ele, envia aos canais
    (digest.channels, ou todos) e marca o envio — o agendado continua daí."""
    from . import digest
    from .notify import NotificationManager

    storage = Storage(cfg.db_path)
    try:
        now = time.time()
        if args.hours:
            start = now - args.hours * 3600
        else:  # desde o último resumo; sem nenhum, o período padrão da agenda
            last = storage.get_meta("digest.last_sent_at")
            span = digest.SCHEDULES[cfg.digest.schedule].total_seconds()
            start = float(last) if last else now - span
        if args.print:
            title, text = digest.render(digest.build(cfg, storage, start, now))
            print(title)
            print(text)
            return 0
        notifier = NotificationManager(build_notifiers(cfg))
        if not notifier:
            print("nenhum canal de notificação configurado — use --print para ver o resumo.",
                  file=sys.stderr)
            return 1
        results = await digest.send(cfg, storage, notifier, start, now, force=True)
        for r in results or []:
            print(f"  {'OK ' if r.ok else 'ERRO'}  {r.channel}" + (f" ({r.error})" if r.error else ""))
        return 0 if results and all(r.ok for r in results) else 1
    finally:
        storage.close()


class _PtFormatter(argparse.HelpFormatter):
    """Ajuda do argparse em português ("uso:" em vez de "usage:")."""

    def add_usage(self, usage, actions, groups, prefix=None):
        return super().add_usage(usage, actions, groups, "uso: " if prefix is None else prefix)


class _Parser(argparse.ArgumentParser):
    def __init__(self, *a, **k):
        k.setdefault("formatter_class", _PtFormatter)
        k["add_help"] = False
        super().__init__(*a, **k)
        self._positionals.title = "argumentos"
        self._optionals.title = "opções"

    def error(self, message):  # noqa: D401 — mesma assinatura do argparse
        for en, pt in _ARGPARSE_PT:
            message = message.replace(en, pt)
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: erro: {message}\n"
                     f"Veja todas as opções com: padme -h\n")


# mensagens do argparse que o usuário vê, em português
_ARGPARSE_PT = (
    ("the following arguments are required", "faltam os argumentos"),
    ("unrecognized arguments", "opção desconhecida"),
    ("expected one argument", "falta o valor"),
    ("invalid choice", "valor inválido"),
    ("choose from", "escolha entre"),
    ("invalid int value", "número inválido"),
    ("invalid float value", "número inválido"),
    ("argument ", "argumento "),
)


# ordem em que os comandos aparecem no `padme -h`
_COMMAND_ORDER = ["monitor", "init", "web", "scan", "finding", "digest", "events",
                  "export", "doctor", "health", "backup", "api", "merge"]

_EXAMPLES = """\
Exemplos:
  padme                         monitora os alvos e abre o painel (http://127.0.0.1:8787)
  padme init                    cria o config com algumas perguntas
  padme --no-web --once         uma varredura, sem painel, e sai (para cron)
  padme scan                    uma varredura agora, mostrando o que mudou
  padme finding list            problemas abertos
  padme finding suppress ID --reason "falso positivo"
  padme digest --print          resumo do período no terminal
  padme --update                atualiza para a versão mais recente do GitHub
"""


def _action_line(a: argparse.Action) -> tuple[str, str]:
    metavar = " ".join(a.metavar) if isinstance(a.metavar, tuple) else a.metavar
    choices = ("{" + ",".join(map(str, a.choices)) + "}") if a.choices else ""
    if a.option_strings:
        names = ", ".join(a.option_strings)
        if a.nargs != 0:
            names += " " + (metavar or choices or a.dest.upper())
    else:
        names = metavar or choices or a.dest
    return names, (a.help or "").replace("%%", "%")


class _FullHelp(argparse.Action):
    """`padme -h`: TODOS os comandos com TODAS as opções, numa tela só."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS,
                 help=None):  # noqa: A002 — nome do argparse
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(full_help(parser))
        parser.exit()


def full_help(parser: argparse.ArgumentParser) -> str:
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps = {ca.dest: ca.help for ca in sub._choices_actions}
    out = ["Padmé — monitoramento da superfície de ataque dos SEUS domínios.", "",
           "uso: padme [opções gerais] [comando] [opções do comando]", "",
           "Sem comando, o padme monitora os alvos e abre o painel web (= padme monitor);",
           "as opções do monitor valem direto, ex.: padme --no-web --interval 600.", "",
           "Comandos:"]
    for name in _COMMAND_ORDER:
        sp = sub.choices[name]
        out.append(f"  {name:<12}{helps.get(name, '')}")
        for a in sp._actions:
            if isinstance(a, argparse._HelpAction):
                continue
            names, text = _action_line(a)
            out.append(f"      {names:<26}{text}" if len(names) < 26
                       else f"      {names}\n      {'':<26}{text}")
    out += ["", "Opções gerais:"]
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            continue
        names, text = _action_line(a)
        out.append(f"  {names:<28}{text}")
    out += ["", _EXAMPLES,
            f"Config em uso: {find_config(None)} (mude com -c ou PADME_CONFIG)",
            "Cada comando também tem ajuda própria: padme COMANDO -h"]
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="padme",
                description="Padmé — monitoramento da superfície de ataque dos SEUS domínios.")
    p.add_argument("-h", "--help", action=_FullHelp, help="mostra esta ajuda (todos os comandos e opções)")
    p.add_argument("-c", "--config", default=None, metavar="ARQUIVO",
                   help="config YAML (padrão: PADME_CONFIG, ./config.yaml ou a pasta do usuário)")
    p.add_argument("-v", "--verbose", action="store_true", help="log detalhado")
    p.add_argument("--update", action="store_true",
                   help="atualiza o padme para a versão mais recente do GitHub")
    p.add_argument("--force", action="store_true", help="com --update: reinstala mesmo se já estiver atualizado")
    p.add_argument("--version", action="version", version=f"padme {__version__}",
                   help="mostra a versão")

    sub = p.add_subparsers(dest="command", metavar="comando", parser_class=_Parser)

    def cmd(name: str, text: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=text, description=text)
        sp.add_argument("-h", "--help", action="help", help="mostra a ajuda deste comando")
        return sp

    mp = cmd("monitor", "monitora em loop, alerta nos canais e serve o painel web (comando padrão)")
    mp.add_argument("--no-web", action="store_true", help="não abre o painel web junto")
    mp.add_argument("--web-host", default=None, metavar="HOST",
                    help="endereço do painel (padrão: web.bind do config, 127.0.0.1)")
    mp.add_argument("--web-port", type=int, default=None, metavar="PORTA",
                    help="porta do painel (padrão: web.port do config, 8787)")
    mp.add_argument("--allow-no-auth", action="store_true",
                    help="painel fora de localhost SEM token (decisão consciente)")
    mp.add_argument("--interval", type=int, default=None, metavar="SEG",
                    help="segundos entre varreduras (sobrescreve interval_seconds)")
    mp.add_argument("--level", choices=_LEVEL_CHOICES, default=None,
                    help="severidade mínima enviada aos canais (sobrescreve o config)")
    mp.add_argument("--once", action="store_true", help="uma varredura e sai, sem painel (para cron)")
    mp.add_argument("--lock", default=None, metavar="ARQUIVO",
                    help="trava de instância única: sai se já houver um padme rodando")
    mp.set_defaults(func=_cmd_monitor)

    ip = cmd("init", "cria o config com algumas perguntas (domínios, autorização, Telegram)")
    ip.add_argument("--target", action="append", metavar="DOMINIO",
                    help="domínio a monitorar, sem perguntas (repita para vários)")
    ip.add_argument("--yes", action="store_true",
                    help="com --target: confirma que você tem autorização para monitorar")
    ip.add_argument("--force", action="store_true", help="sobrescreve um config existente")

    wb = cmd("web", "só o painel web, sem monitorar (ex.: em outra máquina)")
    wb.add_argument("--host", default=None, help="endereço (padrão: web.bind do config, 127.0.0.1)")
    wb.add_argument("--port", type=int, default=None, metavar="PORTA",
                    help="porta (padrão: web.port do config, 8787)")
    wb.add_argument("--allow-no-auth", action="store_true",
                    help="permite servir fora de localhost SEM token (decisão consciente)")
    wb.set_defaults(func=_cmd_web)

    sp = cmd("scan", "uma varredura agora, mostrando o que mudou")
    sp.add_argument("--notify", action="store_true", help="também envia as mudanças aos canais")
    sp.add_argument("--level", choices=_LEVEL_CHOICES, default=None,
                    help="severidade mínima enviada aos canais (sobrescreve o config)")
    sp.set_defaults(func=_cmd_scan)

    fp = cmd("finding", "problemas abertos: listar, reconhecer, silenciar, aceitar, reabrir")
    fp.add_argument("action", choices=["list", "show", *ACTIONS], metavar="ação",
                    help="list | show ID | ack ID | suppress ID | accept ID | reopen ID")
    fp.add_argument("id", nargs="?", metavar="ID", help="id do problema (ou os 6+ primeiros caracteres)")
    fp.add_argument("--reason", metavar="TEXTO", help="motivo (obrigatório em suppress e accept)")
    fp.add_argument("--by", metavar="NOME", help="quem está agindo (padrão: usuário do sistema)")
    fp.add_argument("--target", metavar="DOMINIO", help="list: só este alvo")
    fp.add_argument("--status", choices=list(STATUSES), help="list: só este status")
    fp.add_argument("--all", action="store_true", help="list: inclui tratados e resolvidos")
    fp.set_defaults(func=_cmd_finding)

    dg = cmd("digest", "resumo do período: mudanças, problemas abertos, saúde da coleta")
    dg.add_argument("--print", action="store_true", help="só mostra no terminal (não envia)")
    dg.add_argument("--hours", type=float, metavar="N", help="últimas N horas (padrão: desde o último resumo)")
    dg.set_defaults(func=_cmd_digest)

    ep = cmd("events", "histórico de mudanças gravado")
    ep.add_argument("--limit", type=int, default=30, metavar="N", help="quantos eventos por alvo (padrão 30)")
    ep.set_defaults(func=_cmd_events)

    xp = cmd("export", "exporta o estado atual em JSON ou CSV")
    xp.add_argument("--format", choices=["json", "csv"], default="json", help="formato (padrão json)")
    xp.add_argument("--out", default=None, metavar="ARQUIVO", help="arquivo de saída (padrão: tela)")
    xp.set_defaults(func=_cmd_export)

    dp = cmd("doctor", "diagnóstico: banco, saúde das varreduras, config e rede")
    dp.set_defaults(func=_cmd_doctor)

    hp = cmd("health", "o monitor está varrendo? (sai com 0 ou 1; para Docker/cron)")
    hp.add_argument("--max-age", type=int, default=None, metavar="SEG",
                    help="idade máxima da última varredura (padrão: 2x o intervalo + 10 min)")
    hp.set_defaults(func=_cmd_health)

    bk = cmd("backup", "cópia consistente do banco (pode rodar com o monitor ligado)")
    bk.add_argument("--out", default=None, metavar="ARQUIVO",
                    help="destino (padrão: padme-backup-<data>.db)")
    bk.set_defaults(func=_cmd_backup)

    ap = cmd("api", "API JSON somente leitura para automação (/api/v1)")
    ap.add_argument("--host", default=None, help="endereço (padrão: api.bind do config, 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None, metavar="PORTA",
                    help="porta (padrão: api.port do config, 8788)")
    ap.add_argument("--allow-no-auth", action="store_true",
                    help="permite servir fora de localhost SEM token (decisão consciente)")
    ap.set_defaults(func=_cmd_api)

    mg = cmd("merge", "compara exports de várias máquinas (multi-vantage)")
    mg.add_argument("files", nargs="+", metavar="ARQUIVO", help="exports JSON, um por máquina")
    mg.add_argument("--out", default=None, metavar="ARQUIVO", help="grava a consolidação em JSON")
    mg.set_defaults(func=_cmd_merge)

    return p


# comandos que não varrem alvos não exigem a confirmação de escopo
_NO_SCOPE = {"events", "export", "web", "api", "doctor", "merge", "backup", "health",
             "finding", "digest"}


def _load_env(config_path: Path) -> None:
    """Segredos do `.env`: o que está ao lado do config e o da pasta atual."""
    beside = config_path.parent / ".env"
    if beside.is_file():
        load_dotenv(beside)
    load_dotenv(os.path.join(os.getcwd(), ".env"))


_GLOBAL_FLAGS = {"-v", "--verbose", "--update", "--force"}
_GLOBAL_WITH_VALUE = {"-c", "--config"}


def _with_default_command(argv: list[str]) -> list[str]:
    """Sem comando, o comando é `monitor`: `padme`, `padme --no-web` e
    `padme -c x.yaml --level high` viram `padme ... monitor ...`.

    Pula as opções gerais do começo; se o que vem depois é uma opção (ou nada),
    insere `monitor` ali. Uma palavra solta continua indo para o argparse, para
    um comando digitado errado dar "comando inválido" e não virar monitor.
    """
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in _GLOBAL_WITH_VALUE:
            i += 2
        elif a in _GLOBAL_FLAGS or a.startswith("--config=") or (a.startswith("-c") and len(a) > 2):
            i += 1
        else:
            break
    if i > len(argv) or (i < len(argv) and (not argv[i].startswith("-")
                                            or argv[i] in ("-h", "--help", "--version"))):
        return argv   # `-c` sem valor, comando escrito ou ajuda: o argparse decide
    return [*argv[:i], "monitor", *argv[i:]]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    args = parser.parse_args(_with_default_command(argv))
    if args.update:
        from .updater import run as update
        return update(force=args.force)
    if args.command is None:
        parser.print_help()
        return 2

    config_path = find_config(args.config)
    if args.command == "init":
        from .initcfg import run as init
        return init(config_path, targets=args.target, yes=args.yes, force=args.force)

    _load_env(config_path)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    # nunca vaza token/secret no log (mesmo com -v): sobe httpx p/ WARNING e
    # mascara segredos conhecidos em qualquer mensagem.
    install_secret_redaction()

    if not config_path.is_file():
        if args.command == "monitor" and not args.once and sys.stdin.isatty():
            print("Nenhum config encontrado. Vamos criar um agora.\n")
            from .initcfg import run as init
            if init(config_path) != 0:
                return 2
            print()
            _load_env(config_path)
        else:
            print(f"Nenhum config encontrado (procurado em {config_path}).\n"
                  "Crie um com:  padme init", file=sys.stderr)
            return 2
    try:
        cfg = Config.load(config_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Erro no config {config_path}: {exc}", file=sys.stderr)
        return 2

    for w in cfg.warnings:  # typo no YAML: avisa em vez de ignorar calado
        print(f"aviso de config: {w}", file=sys.stderr)

    if not cfg.scope_confirmed and args.command not in _NO_SCOPE:
        print(
            "AVISO: scope_confirmed está false no config.\n"
            "  Confirme que você é dono ou tem AUTORIZAÇÃO para monitorar os alvos\n"
            f"  e coloque 'scope_confirmed: true' em {config_path} para prosseguir.",
            file=sys.stderr,
        )
        return 3

    return asyncio.run(args.func(cfg, args))


if __name__ == "__main__":
    raise SystemExit(main())
