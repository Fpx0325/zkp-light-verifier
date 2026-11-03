"""Store verification outcomes with one SQLite transaction per run."""

import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

from .core.verify_logic import Verdict

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class LogEntry:
    id: int
    run_id: str
    checked_at_utc: str
    source: str
    position: int
    verdict: Verdict


@dataclass(frozen=True)
class Totals:
    total: int
    accepted: int
    rejected: int
    acceptance_rate: float | None


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def _connect(self):
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
                return
            if version != 0:
                raise sqlite3.DatabaseError(f"Unsupported audit database schema version: {version}.")
            connection.execute("""
                CREATE TABLE audit_runs (
                    id TEXT PRIMARY KEY,
                    checked_at_utc TEXT NOT NULL,
                    source TEXT NOT NULL CHECK (source IN ('cli', 'api', 'demo'))
                )
            """)
            connection.execute("""
                CREATE TABLE audit_checks (
                    id INTEGER PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES audit_runs(id),
                    position INTEGER NOT NULL CHECK (position > 0),
                    verdict TEXT NOT NULL,
                    UNIQUE (run_id, position)
                )
            """)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def append(self, run_id: str, checked_at: str, source: str, verdicts: list[Verdict]) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO audit_runs VALUES (?, ?, ?)", (run_id, checked_at, source))
            connection.executemany(
                "INSERT INTO audit_checks (run_id, position, verdict) VALUES (?, ?, ?)",
                ((run_id, position, verdict.value) for position, verdict in enumerate(verdicts, 1)),
            )

    def recent(self, limit: int, before_id: int | None = None) -> list[LogEntry]:
        last_id = before_id - 1 if before_id is not None else 2**63 - 1
        with self._connect() as connection:
            rows = connection.execute("""
                SELECT c.id, c.run_id, r.checked_at_utc, r.source, c.position, c.verdict
                FROM audit_checks c JOIN audit_runs r ON r.id = c.run_id
                WHERE c.id <= ?
                ORDER BY c.id DESC LIMIT ?
            """, (last_id, limit))
            return [LogEntry(*row[:-1], Verdict(row[-1])) for row in rows]

    def stats(self) -> dict[str, Totals]:
        totals = {"verification": Totals(0, 0, 0, None), "demo": Totals(0, 0, 0, None)}
        with self._connect() as connection:
            rows = connection.execute("""
                SELECT CASE WHEN r.source = 'demo' THEN 'demo' ELSE 'verification' END AS kind,
                       COUNT(*), SUM(c.verdict = 'verified')
                FROM audit_checks c JOIN audit_runs r ON r.id = c.run_id
                GROUP BY kind
            """)
            for kind, total, accepted in rows:
                totals[kind] = Totals(total, accepted, total - accepted, accepted / total)
        return totals
