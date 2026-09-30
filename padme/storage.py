"""Persistência em SQLite: estado atual + histórico de eventos + metadados de scan.

Tabelas:
  state   -> foto atual da superfície (um Record por linha, com first/last seen)
  events  -> log imutável do que mudou (added/removed/changed)
  targets -> metadados por alvo (baseline, timestamps de scan)

O diff acontece comparando os Records novos de um scan contra o `state`
guardado do alvo. É aqui que o "o que mudou?" ganha memória.

Confiabilidade (P0):
  - 1º scan de um alvo = BASELINE: grava o estado sem gerar eventos (o histórico
    e o gráfico de tendência não são poluídos por "tudo é novo").
  - "alvo conhecido" vem da tabela `targets` (baseline_initialized), não de
    `state` não-vazio — um scan válido com zero records ainda deixa o alvo
    conhecido.
  - REMOVED só é gerado para ESCOPOS que foram observados autoritativamente
    neste scan (`observed_scopes`). Um erro de coleta preserva o estado.

Migração: versionada por `PRAGMA user_version` — bancos antigos ganham a tabela
`targets` com backfill (alvos já existentes contam como baseline concluído, sem
re-baseline).
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import COLLECTOR_OF, Event, EventType, Kind, Record, scope_of, subject_host


def _jdump(meta: dict | None) -> str | None:
    return json.dumps(meta, ensure_ascii=False, sort_keys=True) if meta else None


def _jload(raw) -> dict:
    if not raw:
        return {}
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}

def _row_to_event(r) -> Event:
    keys = r.keys()
    return Event(
        target=r["target"],
        event_type=EventType(r["event_type"]),
        kind=Kind(r["kind"]),
        key=r["key"],
        old_value=r["old_value"],
        new_value=r["new_value"],
        event_id=r["event_id"] if "event_id" in keys else None,
        scan_id=r["scan_id"] if "scan_id" in keys else None,
        detected_at=datetime.fromtimestamp(
            r["ts"], tz=timezone.utc).isoformat(timespec="seconds"),
        metadata=_jload(r["metadata"]) if "metadata" in keys else {},
    )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS state (
    target     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    PRIMARY KEY (target, kind, key)
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT NOT NULL,
    ts         REAL NOT NULL,
    event_type TEXT NOT NULL,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_target_ts ON events (target, ts);
CREATE TABLE IF NOT EXISTS targets (
    target               TEXT PRIMARY KEY,
    first_scan_at        REAL,
    last_scan_at         REAL,
    last_success_at      REAL,
    baseline_initialized INTEGER NOT NULL DEFAULT 0
);
-- alerta grave que um CANAL não conseguiu entregar: reenviado no próximo ciclo
-- (e após reinício). Uma linha por (evento, canal) — cada canal tem seu destino.
CREATE TABLE IF NOT EXISTS pending_notifications (
    event_id   TEXT NOT NULL,
    channel    TEXT NOT NULL,
    target     TEXT NOT NULL,
    created_at REAL NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (event_id, channel)
);
"""

_SCHEMA_VERSION = 8  # v7: pending_notifications (criada pelo _SCHEMA); v8: DNS agregado


class StorageOutdated(RuntimeError):
    """Banco em versão de schema anterior, aberto em modo somente leitura (que
    não migra). Rode o `monitor`/`scan` ou `padme doctor` uma vez para migrar."""


class Storage:
    def __init__(self, db_path: str | Path, readonly: bool = False):
        """`readonly=True` (painel/export): abre com `mode=ro` — nenhuma escrita,
        DDL ou migração; não disputa lock com o monitor e funciona em volume
        montado só-leitura. Banco inexistente -> FileNotFoundError; schema
        antigo -> StorageOutdated (quem migra é o processo de escrita)."""
        self.db_path = str(db_path)
        self.readonly = readonly
        if readonly:
            path = Path(self.db_path)
            if not path.is_file():
                raise FileNotFoundError(f"banco não encontrado: {self.db_path}")
            self._conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True,
                                         timeout=5.0)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA busy_timeout=3000")  # configuração da conexão, não escrita
            ver = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if ver < _SCHEMA_VERSION:
                self._conn.close()
                raise StorageOutdated(
                    f"banco na versão {ver}, esta versão do PADME espera {_SCHEMA_VERSION}: "
                    "rode o monitor/scan ou `padme doctor` uma vez para migrar.")
            return
        self._conn = sqlite3.connect(self.db_path, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        # WAL + busy_timeout: leitura (web/export) e escrita (monitor) simultâneas
        # no mesmo banco sem "database is locked".
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=3000")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _has_column(self, table: str, col: str) -> bool:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r["name"] == col for r in rows)

    def _migrate(self) -> None:
        """Migração idempotente e incremental baseada em PRAGMA user_version."""
        ver = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if ver < 1:
            # v0 -> v1: bancos pré-`targets`. Os alvos que já têm estado são
            # baselines concluídos — marca como inicializados p/ não re-baselinar.
            self._conn.execute(
                "INSERT OR IGNORE INTO targets "
                "(target, first_scan_at, last_scan_at, last_success_at, baseline_initialized) "
                "SELECT target, MIN(first_seen), MAX(last_seen), MAX(last_seen), 1 "
                "FROM state GROUP BY target"
            )
        if ver < 2:
            # v1 -> v2: rastreio de eventos (dedup no n8n, troubleshooting).
            for col in ("event_id", "scan_id"):
                if not self._has_column("events", col):
                    self._conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
        if ver < 3:
            # v2 -> v3: saúde da coleta por alvo (o painel precisa saber se o
            # que mostra é o estado real ou o resultado de uma coleta parcial).
            for col in ("last_error_count", "last_partial", "last_duration_ms"):
                if not self._has_column("targets", col):
                    self._conn.execute(f"ALTER TABLE targets ADD COLUMN {col} INTEGER")
        if ver < 4:
            # v3 -> v4: metadata estruturada (JSON) por record e por evento.
            for tbl in ("state", "events"):
                if not self._has_column(tbl, "metadata"):
                    self._conn.execute(f"ALTER TABLE {tbl} ADD COLUMN metadata TEXT")
        if ver < 5:
            # v4 -> v5: saúde POR COLLECTOR do último scan (JSON em targets).
            if not self._has_column("targets", "collectors_health"):
                self._conn.execute("ALTER TABLE targets ADD COLUMN collectors_health TEXT")
        if ver < 6:
            # v5 -> v6: coletas INCONCLUSIVAS do último scan (timeout sem exceção),
            # separadas dos erros — "coleta ok · N inconclusivos" no painel.
            if not self._has_column("targets", "last_inconclusive"):
                self._conn.execute("ALTER TABLE targets ADD COLUMN last_inconclusive INTEGER")
        if ver < 8:
            self._migrate_dns_aggregate()
        if ver != _SCHEMA_VERSION:
            self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def _migrate_dns_aggregate(self) -> None:
        """v7 -> v8: DNS passa de uma linha por resposta (`host|TIPO|valor`) para
        uma por (host, tipo) com o conjunto (`host|TIPO`). Converte o ESTADO
        existente no mesmo formato que o collector gera, então o 1º scan após o
        upgrade não produz uma rajada de REMOVED+ADDED. O histórico de eventos
        fica como está (a formatação lê os dois formatos)."""
        rows = self._conn.execute(
            "SELECT target, key, value, first_seen, last_seen FROM state WHERE kind = 'dns'"
        ).fetchall()
        groups: dict[tuple[str, str], dict] = {}
        for r in rows:
            parts = r["key"].split("|", 2)
            if len(parts) != 3:
                continue  # já agregado
            g = groups.setdefault((r["target"], f"{parts[0]}|{parts[1]}"), {
                "vals": set(), "old": [], "first": r["first_seen"], "last": r["last_seen"]})
            g["vals"].add(parts[2] or r["value"])
            g["old"].append(r["key"])
            g["first"] = min(g["first"], r["first_seen"])
            g["last"] = max(g["last"], r["last_seen"])
        for (target, key), g in groups.items():
            self._conn.executemany(
                "DELETE FROM state WHERE target = ? AND kind = 'dns' AND key = ?",
                [(target, k) for k in g["old"]])
            vals = sorted(g["vals"])
            self._conn.execute(
                "INSERT OR REPLACE INTO state (target, kind, key, value, first_seen, last_seen, metadata)"
                " VALUES (?,?,?,?,?,?,?)",
                (target, "dns", key, ", ".join(vals), g["first"], g["last"], _jdump({"values": vals})))

    def close(self) -> None:
        self._conn.close()

    # -- leitura -----------------------------------------------------------
    def load_state(self, target: str) -> dict[tuple[str, str], str]:
        cur = self._conn.execute(
            "SELECT kind, key, value FROM state WHERE target = ?", (target,)
        )
        return {(r["kind"], r["key"]): r["value"] for r in cur.fetchall()}

    def load_state_full(self, target: str) -> dict[tuple[str, str], dict]:
        """Estado atual com value E metadata (JSON decodificado) — usado pelo
        diff semântico p/ saber QUAL campo mudou num CHANGED."""
        cur = self._conn.execute(
            "SELECT kind, key, value, metadata FROM state WHERE target = ?", (target,)
        )
        return {(r["kind"], r["key"]): {"value": r["value"], "metadata": _jload(r["metadata"])}
                for r in cur.fetchall()}

    def is_known_target(self, target: str) -> bool:
        """Alvo já teve um baseline gravado? (independe de `state` estar vazio)."""
        cur = self._conn.execute(
            "SELECT 1 FROM targets WHERE target = ? AND baseline_initialized = 1 LIMIT 1",
            (target,),
        )
        return cur.fetchone() is not None

    def target_meta(self, target: str) -> dict | None:
        cur = self._conn.execute("SELECT * FROM targets WHERE target = ?", (target,))
        row = cur.fetchone()
        if not row:
            return None
        d = dict(row)
        if "collectors_health" in d:  # JSON -> dict (saúde por collector)
            d["collectors_health"] = _jload(d.get("collectors_health"))
        return d

    def all_state(self, targets: list[str] | None = None) -> list[dict]:
        """Estado atual completo (para export), opcionalmente filtrado por alvo.
        `metadata` volta como dict (JSON decodificado)."""
        q = "SELECT target, kind, key, value, first_seen, last_seen, metadata FROM state"
        params: tuple = ()
        if targets:
            q += f" WHERE target IN ({','.join('?' * len(targets))})"
            params = tuple(targets)
        q += " ORDER BY target, kind, key"
        out = []
        for r in self._conn.execute(q, params).fetchall():
            d = dict(r)
            d["metadata"] = _jload(d.get("metadata"))
            out.append(d)
        return out

    def events_per_day(self, target: str, days: int = 30) -> list[dict]:
        """Série densa dos últimos `days` dias: contagem de eventos por tipo por
        dia (added/removed/changed). Dias sem evento vêm com zero, então o
        gráfico fica com espaçamento uniforme. Base pra 'a superfície está
        crescendo ou estável?'.

        Registros DNS ficam FORA: rotação de IP de CDN não é a superfície
        crescendo, e dominava o gráfico. Continuam na timeline e no histórico."""
        cur = self._conn.execute(
            "SELECT strftime('%Y-%m-%d', ts, 'unixepoch', 'localtime') AS day,"
            "       event_type, COUNT(*) AS n"
            " FROM events WHERE target = ? AND kind != 'dns'"
            "   AND ts >= strftime('%s', 'now', ?)"
            " GROUP BY day, event_type",
            (target, f"-{max(1, days) - 1} days"),
        )
        counts: dict[str, dict[str, int]] = {}
        for r in cur.fetchall():
            counts.setdefault(r["day"], {})[r["event_type"]] = r["n"]

        today = datetime.now().date()
        out: list[dict] = []
        for i in range(max(1, days) - 1, -1, -1):
            day = (today - timedelta(days=i)).isoformat()
            c = counts.get(day, {})
            added = c.get("added", 0)
            removed = c.get("removed", 0)
            changed = c.get("changed", 0)
            out.append({
                "day": day, "added": added, "removed": removed,
                "changed": changed, "total": added + removed + changed,
            })
        return out

    def recent_event_counts(self, target: str, since_ts: float) -> dict[tuple[str, str], int]:
        """Quantos eventos cada (kind, key) acumulou desde `since_ts` — base do
        amortecimento de flapping."""
        cur = self._conn.execute(
            "SELECT kind, key, COUNT(*) AS n FROM events"
            " WHERE target = ? AND ts >= ? GROUP BY kind, key",
            (target, since_ts),
        )
        return {(r["kind"], r["key"]): r["n"] for r in cur.fetchall()}

    def recent_events(self, target: str, limit: int = 50) -> list[Event]:
        cur = self._conn.execute(
            "SELECT * FROM events WHERE target = ? ORDER BY ts DESC LIMIT ?",
            (target, limit),
        )
        return [_row_to_event(r) for r in cur.fetchall()]

    def events_by_ids(self, event_ids: list[str]) -> list[Event]:
        """Eventos pelos `event_id` (ordem cronológica). Ids que a retenção já
        apagou simplesmente não voltam."""
        if not event_ids:
            return []
        q = ("SELECT * FROM events WHERE event_id IN (" + ",".join("?" * len(event_ids))
             + ") ORDER BY ts, id")
        return [_row_to_event(r) for r in self._conn.execute(q, tuple(event_ids)).fetchall()]

    # -- alertas não entregues (reenvio) ----------------------------------
    def queue_notifications(self, channel: str, target: str, event_ids: list[str]) -> None:
        """Marca eventos que `channel` falhou em entregar. Idempotente."""
        now = time.time()
        self._conn.executemany(
            "INSERT OR IGNORE INTO pending_notifications (event_id, channel, target, created_at)"
            " VALUES (?,?,?,?)",
            [(eid, channel, target, now) for eid in event_ids if eid],
        )
        self._conn.commit()

    def pending_notifications(self, channel: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT event_id, target, created_at, attempts FROM pending_notifications"
            " WHERE channel = ? ORDER BY created_at", (channel,))
        return [dict(r) for r in cur.fetchall()]

    def pending_counts(self) -> dict[str, int]:
        cur = self._conn.execute(
            "SELECT channel, COUNT(*) AS n FROM pending_notifications GROUP BY channel")
        return {r["channel"]: r["n"] for r in cur.fetchall()}

    def resolve_notifications(self, channel: str, event_ids: list[str]) -> None:
        """Entregues (ou abandonadas): saem da fila."""
        self._conn.executemany(
            "DELETE FROM pending_notifications WHERE channel = ? AND event_id = ?",
            [(channel, eid) for eid in event_ids])
        self._conn.commit()

    def bump_notifications(self, channel: str, event_ids: list[str]) -> None:
        """Mais uma tentativa falhou."""
        self._conn.executemany(
            "UPDATE pending_notifications SET attempts = attempts + 1"
            " WHERE channel = ? AND event_id = ?",
            [(channel, eid) for eid in event_ids])
        self._conn.commit()

    # -- escrita (aplica diff e devolve eventos) ---------------------------
    def apply_scan(
        self,
        target: str,
        records: list[Record],
        observed_scopes: set[tuple[str, str]] | None = None,
        *,
        source: str | None = None,
        context_rules: list | None = None,
        complete: bool = True,
    ) -> list[Event]:
        """Aplica um scan.

        1º scan (sem baseline) -> grava o estado como BASELINE e devolve []
        (nada de "tudo é novo" no histórico). Depois disso, faz o diff normal.

        `complete=False` (algum collector falhou): a baseline fica PROVISÓRIA —
        o próximo scan também é tratado como baseline (soma o que faltou, sem
        gerar eventos) e aí consolida. Sem isso, o que a coleta parcial deixou de
        ver viraria uma enxurrada de ADDED no primeiro scan limpo. Só uma
        repetição: um alvo com falha crônica não fica sem baseline para sempre.

        `observed_scopes` (de engine): só os escopos aí presentes podem gerar
        REMOVED; ausência em escopo NÃO observado preserva o estado (erro de
        coleta != remoção). `None` = compat: todos os escopos são removíveis.

        `source`/`context_rules` (proveniência + contexto): carimbam no metadata
        do evento a fonte (vantage), o collector de origem e o contexto do ativo,
        e detalham CHANGED por campo semântico. Opcionais — sem eles, o
        comportamento é o de antes.
        """
        from .context import resolve as resolve_ctx
        from .differ import diff, field_changes  # import tardio p/ evitar ciclo

        now = time.time()
        baseline = not self.is_known_target(target)
        cur = self._conn.cursor()

        if baseline:
            # já existe linha em `targets` sem baseline = houve baseline provisória
            retry = self._conn.execute(
                "SELECT 1 FROM targets WHERE target = ? LIMIT 1", (target,)).fetchone() is not None
            # soma ao que a tentativa provisória gravou (não apaga nada na baseline)
            self._write_state(cur, target, records, now, prior=self.load_state(target))
            self._mark_scan(cur, target, now, initialized=complete or retry)
            self._conn.commit()
            return []

        old_full = self.load_state_full(target)
        old = {k: v["value"] for k, v in old_full.items()}
        new = {r.ident(): r.value for r in records}
        events = diff(target, old, new)

        # trava de remoção: só remove/gera REMOVED em escopo observado
        kept: list[Event] = []
        removable_keys: set[tuple[str, str]] = set()
        for e in events:
            if e.event_type == EventType.REMOVED:
                scope = scope_of(e.kind, e.key, target)
                if observed_scopes is not None and scope not in observed_scopes:
                    continue  # escopo não observado -> preserva, não reporta
                removable_keys.add((e.kind.value, e.key))
            kept.append(e)

        meta_by_ident = {r.ident(): r.metadata for r in records}
        rules = context_rules or []
        scan_id = uuid.uuid4().hex
        detected_at = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="seconds")
        for e in kept:
            e.event_id = uuid.uuid4().hex
            e.scan_id = scan_id
            e.detected_at = detected_at
            # added/changed carregam o metadata do record observado
            md = dict(meta_by_ident.get((e.kind.value, e.key), {}) or {})
            # proveniência: de onde veio a evidência (§6 do roadmap)
            if source:
                md["_source"] = source
            md["_collector"] = COLLECTOR_OF.get(e.kind)
            ctx = resolve_ctx(subject_host(e.kind, e.key, target), target, rules)
            if ctx is not None:
                md["_context"] = ctx.as_dict()
            # diff semântico: QUAL campo mudou (§5 do roadmap)
            if e.event_type == EventType.CHANGED:
                prev = old_full.get((e.kind.value, e.key), {})
                changes = field_changes(e.kind, prev.get("value", ""), prev.get("metadata"),
                                        e.new_value or "", md)
                if changes:
                    md["_changes"] = changes
            e.metadata = md
            cur.execute(
                "INSERT INTO events (target, ts, event_type, kind, key, old_value, new_value, event_id, scan_id, metadata)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (target, now, e.event_type.value, e.kind.value, e.key, e.old_value, e.new_value,
                 e.event_id, e.scan_id, _jdump(e.metadata)),
            )

        self._write_state(cur, target, records, now, prior=old, removable=removable_keys)
        self._mark_scan(cur, target, now)
        self._conn.commit()
        return kept

    # -- helpers de escrita -------------------------------------------------
    def _write_state(self, cur, target: str, records: list[Record], now: float,
                     prior: dict[tuple[str, str], str],
                     removable: set[tuple[str, str]] | None = None) -> None:
        """Upsert dos records observados e remoção só das keys removíveis."""
        seen_keys = set()
        for r in records:
            k = r.ident()
            seen_keys.add(k)
            meta = _jdump(r.metadata)
            if k in prior:
                cur.execute(
                    "UPDATE state SET value=?, last_seen=?, metadata=? WHERE target=? AND kind=? AND key=?",
                    (r.value, now, meta, target, r.kind.value, r.key),
                )
            else:
                cur.execute(
                    "INSERT OR REPLACE INTO state (target, kind, key, value, first_seen, last_seen, metadata)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (target, r.kind.value, r.key, r.value, now, now, meta),
                )
        if removable:
            for (kind, key) in removable:
                if (kind, key) not in seen_keys:
                    cur.execute(
                        "DELETE FROM state WHERE target=? AND kind=? AND key=?",
                        (target, kind, key),
                    )

    def _mark_scan(self, cur, target: str, now: float, initialized: bool = True) -> None:
        """Registra/atualiza os metadados do alvo (baseline + last_scan_at).

        `initialized=False` grava a baseline como provisória; uma baseline já
        consolidada nunca volta a provisória (MAX).

        `last_success_at` NÃO é tocado aqui — quem decide "sucesso" é
        `update_health` (só marca sucesso quando a coleta veio sem erros)."""
        cur.execute(
            "INSERT INTO targets (target, first_scan_at, last_scan_at, baseline_initialized)"
            " VALUES (?,?,?,?)"
            " ON CONFLICT(target) DO UPDATE SET"
            "   last_scan_at=excluded.last_scan_at,"
            "   baseline_initialized=MAX(targets.baseline_initialized,"
            "                            excluded.baseline_initialized)",
            (target, now, now, int(initialized)),
        )

    def update_health(self, target: str, *, error_count: int, partial: bool,
                      duration_ms: int, collectors: dict | None = None,
                      when: float | None = None, inconclusive: int = 0) -> None:
        """Grava a saúde da última coleta do alvo. `last_success_at` só avança
        quando a coleta veio limpa (error_count == 0) — assim o painel distingue
        'último scan' de 'último scan confiável'. `collectors`: status por
        collector do último scan (JSON).

        `inconclusive`: coletas sem resposta (timeout) que NÃO quebraram — estado
        preservado. São mostradas à parte; parcial de verdade continua sendo erro."""
        now = time.time() if when is None else when
        if error_count == 0:
            self._conn.execute(
                "UPDATE targets SET last_scan_at=?, last_success_at=?, last_error_count=?,"
                " last_partial=?, last_duration_ms=? WHERE target=?",
                (now, now, error_count, int(partial), duration_ms, target),
            )
        else:
            self._conn.execute(
                "UPDATE targets SET last_scan_at=?, last_error_count=?,"
                " last_partial=?, last_duration_ms=? WHERE target=?",
                (now, error_count, int(partial), duration_ms, target),
            )
        self._conn.execute("UPDATE targets SET last_inconclusive=? WHERE target=?",
                           (int(inconclusive), target))
        if collectors is not None:
            self._conn.execute("UPDATE targets SET collectors_health=? WHERE target=?",
                               (_jdump(collectors), target))
        self._conn.commit()

    def prune_events(self, retention_days: int) -> int:
        """Apaga eventos mais antigos que `retention_days` (0/negativo = mantém
        tudo). NÃO toca no `state`. Devolve quantas linhas foram removidas."""
        if retention_days <= 0:
            return 0
        cutoff = time.time() - retention_days * 86400
        cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        self._conn.commit()
        return cur.rowcount

    def integrity_check(self) -> str:
        """PRAGMA integrity_check — 'ok' se o banco está íntegro."""
        row = self._conn.execute("PRAGMA integrity_check").fetchone()
        return row[0] if row else "unknown"

    def counts(self) -> dict[str, int]:
        """Contagens rápidas para diagnóstico (padme doctor)."""
        c = self._conn.execute
        return {
            "targets": c("SELECT COUNT(*) FROM targets").fetchone()[0],
            "state": c("SELECT COUNT(*) FROM state").fetchone()[0],
            "events": c("SELECT COUNT(*) FROM events").fetchone()[0],
        }

    def db_size(self) -> dict[str, int]:
        """Tamanho em bytes do banco e do WAL (planejamento de disco/backup)."""
        out = {"db": 0, "wal": 0}
        for label, suffix in (("db", ""), ("wal", "-wal")):
            try:
                out[label] = Path(self.db_path + suffix).stat().st_size
            except OSError:
                pass
        out["total"] = out["db"] + out["wal"]
        return out

    def backup(self, dest_path: str | Path) -> dict:
        """Backup online consistente via API de backup do SQLite
        (`sqlite3.Connection.backup`) — seguro mesmo com o monitor escrevendo,
        e correto sob WAL (não é uma cópia crua do arquivo no meio de uma
        escrita). Devolve o caminho, o tamanho e o integrity_check do destino."""
        dest_path = str(dest_path)
        Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        dest = sqlite3.connect(dest_path, timeout=10.0)
        try:
            with dest:
                self._conn.backup(dest)
            integrity = dest.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            dest.close()
        size = 0
        try:
            size = Path(dest_path).stat().st_size
        except OSError:
            pass
        return {"path": dest_path, "bytes": size, "integrity": integrity}
