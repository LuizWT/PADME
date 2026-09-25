"""Persistência em SQLite: estado atual + histórico de eventos.

Duas tabelas:
  state  -> foto atual da superfície (um Record por linha, com first/last seen)
  events -> log imutável de tudo que mudou (added/removed/changed)

O diff acontece comparando os Records novos de um scan contra o `state`
guardado do alvo. É aqui que o "o que mudou?" ganha memória.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from .models import Event, EventType, Kind, Record

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
"""


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
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- leitura -----------------------------------------------------------
    def load_state(self, target: str) -> dict[tuple[str, str], str]:
        cur = self._conn.execute(
            "SELECT kind, key, value FROM state WHERE target = ?", (target,)
        )
        return {(r["kind"], r["key"]): r["value"] for r in cur.fetchall()}

    def is_known_target(self, target: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM state WHERE target = ? LIMIT 1", (target,)
        )
        return cur.fetchone() is not None

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
    def apply_scan(self, target: str, records: list[Record]) -> list[Event]:
        from .differ import diff  # import tardio p/ evitar ciclo

        old = self.load_state(target)
        new = {r.ident(): r.value for r in records}
        events = diff(target, old, new)

        now = time.time()
        cur = self._conn.cursor()

        # registra eventos
        for e in events:
            cur.execute(
                "INSERT INTO events (target, ts, event_type, kind, key, old_value, new_value)"
                " VALUES (?,?,?,?,?,?,?)",
                (target, now, e.event_type.value, e.kind.value, e.key, e.old_value, e.new_value),
            )

        # atualiza o state para os records atuais
        seen_keys = set()
        for r in records:
            k = r.ident()
            seen_keys.add(k)
            if k in old:
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

        # remove do state o que sumiu
        for (kind, key) in old.keys():
            if (kind, key) not in seen_keys:
                cur.execute(
                    "DELETE FROM state WHERE target=? AND kind=? AND key=?",
                    (target, kind, key),
                )

        self._conn.commit()
        return events
