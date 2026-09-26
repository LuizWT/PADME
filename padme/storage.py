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

import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from .models import Event, EventType, Kind, Record, scope_of

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
"""

_SCHEMA_VERSION = 1


class Storage:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        # WAL + busy_timeout: leitura (web/export) e escrita (monitor) simultâneas
        # no mesmo banco sem "database is locked".
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=3000")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Migração idempotente baseada em PRAGMA user_version."""
        ver = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if ver < 1:
            # Bancos pré-`targets`: os alvos que já têm estado são baselines
            # concluídos — marca como inicializados para não re-baselinar.
            self._conn.execute(
                "INSERT OR IGNORE INTO targets "
                "(target, first_scan_at, last_scan_at, last_success_at, baseline_initialized) "
                "SELECT target, MIN(first_seen), MAX(last_seen), MAX(last_seen), 1 "
                "FROM state GROUP BY target"
            )
            self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def close(self) -> None:
        self._conn.close()

    # -- leitura -----------------------------------------------------------
    def load_state(self, target: str) -> dict[tuple[str, str], str]:
        cur = self._conn.execute(
            "SELECT kind, key, value FROM state WHERE target = ?", (target,)
        )
        return {(r["kind"], r["key"]): r["value"] for r in cur.fetchall()}

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
        return dict(row) if row else None

    def all_state(self, targets: list[str] | None = None) -> list[dict]:
        """Estado atual completo (para export), opcionalmente filtrado por alvo."""
        q = "SELECT target, kind, key, value, first_seen, last_seen FROM state"
        params: tuple = ()
        if targets:
            q += f" WHERE target IN ({','.join('?' * len(targets))})"
            params = tuple(targets)
        q += " ORDER BY target, kind, key"
        return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    def events_per_day(self, target: str, days: int = 30) -> list[dict]:
        """Série densa dos últimos `days` dias: contagem de eventos por tipo por
        dia (added/removed/changed). Dias sem evento vêm com zero, então o
        gráfico fica com espaçamento uniforme. Base pra 'a superfície está
        crescendo ou estável?'."""
        cur = self._conn.execute(
            "SELECT strftime('%Y-%m-%d', ts, 'unixepoch', 'localtime') AS day,"
            "       event_type, COUNT(*) AS n"
            " FROM events WHERE target = ?"
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

    def recent_events(self, target: str, limit: int = 50) -> list[Event]:
        cur = self._conn.execute(
            "SELECT * FROM events WHERE target = ? ORDER BY ts DESC LIMIT ?",
            (target, limit),
        )
        out = []
        for r in cur.fetchall():
            out.append(
                Event(
                    target=r["target"],
                    event_type=EventType(r["event_type"]),
                    kind=Kind(r["kind"]),
                    key=r["key"],
                    old_value=r["old_value"],
                    new_value=r["new_value"],
                )
            )
        return out

    # -- escrita (aplica diff e devolve eventos) ---------------------------
    def apply_scan(
        self,
        target: str,
        records: list[Record],
        observed_scopes: set[tuple[str, str]] | None = None,
    ) -> list[Event]:
        """Aplica um scan.

        1º scan (sem baseline) -> grava o estado como BASELINE e devolve []
        (nada de "tudo é novo" no histórico). Depois disso, faz o diff normal.

        `observed_scopes` (de engine): só os escopos aí presentes podem gerar
        REMOVED; ausência em escopo NÃO observado preserva o estado (erro de
        coleta != remoção). `None` = compat: todos os escopos são removíveis.
        """
        from .differ import diff  # import tardio p/ evitar ciclo

        now = time.time()
        baseline = not self.is_known_target(target)
        cur = self._conn.cursor()

        if baseline:
            self._write_state(cur, target, records, now, prior={})
            self._mark_scan(cur, target, now, baseline=True)
            self._conn.commit()
            return []

        old = self.load_state(target)
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

        for e in kept:
            cur.execute(
                "INSERT INTO events (target, ts, event_type, kind, key, old_value, new_value)"
                " VALUES (?,?,?,?,?,?,?)",
                (target, now, e.event_type.value, e.kind.value, e.key, e.old_value, e.new_value),
            )

        self._write_state(cur, target, records, now, prior=old, removable=removable_keys)
        self._mark_scan(cur, target, now, baseline=False)
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
            if k in prior:
                cur.execute(
                    "UPDATE state SET value=?, last_seen=? WHERE target=? AND kind=? AND key=?",
                    (r.value, now, target, r.kind.value, r.key),
                )
            else:
                cur.execute(
                    "INSERT OR REPLACE INTO state (target, kind, key, value, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?)",
                    (target, r.kind.value, r.key, r.value, now, now),
                )
        if removable:
            for (kind, key) in removable:
                if (kind, key) not in seen_keys:
                    cur.execute(
                        "DELETE FROM state WHERE target=? AND kind=? AND key=?",
                        (target, kind, key),
                    )

    def _mark_scan(self, cur, target: str, now: float, baseline: bool) -> None:
        """Registra/atualiza os metadados do alvo (baseline + timestamps)."""
        cur.execute(
            "INSERT INTO targets (target, first_scan_at, last_scan_at, last_success_at, baseline_initialized)"
            " VALUES (?,?,?,?,1)"
            " ON CONFLICT(target) DO UPDATE SET"
            "   last_scan_at=excluded.last_scan_at,"
            "   last_success_at=excluded.last_success_at,"
            "   baseline_initialized=1",
            (target, now, now, now),
        )
