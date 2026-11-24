"""SQLite case store. One database holds cases, evidence, notes, recovery runs, recovered files,
sanitization jobs and the append-only audit ledger."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS examiners (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, organization TEXT, badge TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT, examiner TEXT, organization TEXT,
    status TEXT DEFAULT 'open', created_at TEXT);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), label TEXT, path TEXT NOT NULL,
    kind TEXT NOT NULL,            -- original | working-copy | device
    parent_id INTEGER, size INTEGER, sha256 TEXT, md5 TEXT, media_profile TEXT,
    acquired_at TEXT, acquired_by TEXT, notes TEXT, sanitized INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY, case_id TEXT NOT NULL, author TEXT, body TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS recovery_runs (
    id INTEGER PRIMARY KEY, case_id TEXT, evidence_id INTEGER, started_at TEXT, finished_at TEXT,
    options TEXT, stats TEXT, partitions TEXT, out_dir TEXT, pre_sha256 TEXT, post_sha256 TEXT,
    source_unchanged INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS recovered_files (
    id INTEGER PRIMARY KEY, run_id INTEGER, case_id TEXT, evidence_id INTEGER, item_id INTEGER,
    source TEXT, name TEXT, path TEXT, offset INTEGER, size INTEGER, deleted INTEGER,
    detected_type TEXT, mime TEXT, claimed_ext TEXT, ext_mismatch INTEGER, validation_status TEXT,
    confidence INTEGER, fragmentation TEXT, sha256 TEXT, md5 TEXT, output_path TEXT,
    thumbnail_path TEXT, superseded_by INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS sanitizations (
    id INTEGER PRIMARY KEY, case_id TEXT, evidence_id INTEGER, target TEXT, method TEXT,
    nist_category TEXT, started_at TEXT, finished_at TEXT, result TEXT, verification TEXT,
    certificate_id TEXT, certificate_json TEXT, certificate_pdf TEXT, operator TEXT, dry_run INTEGER);
CREATE TABLE IF NOT EXISTS ledger (
    seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
    case_id TEXT, evidence_id INTEGER, details TEXT NOT NULL, prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL, signature TEXT);
CREATE TABLE IF NOT EXISTS anchors (
    id INTEGER PRIMARY KEY, seq INTEGER, head_hash TEXT, merkle_root TEXT, exported_at TEXT, path TEXT);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
    BEGIN SELECT RAISE(ABORT, 'audit ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
    BEGIN SELECT RAISE(ABORT, 'audit ledger is append-only'); END;
CREATE INDEX IF NOT EXISTS ix_ledger_case ON ledger(case_id);
CREATE INDEX IF NOT EXISTS ix_files_run ON recovered_files(run_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    @contextmanager
    def tx(self):
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql: str, args=()) -> dict | None:
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def insert(self, table: str, row: dict) -> int:
        cols = ",".join(row)
        qs = ",".join("?" for _ in row)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in row.values()]
        with self.tx() as c:
            return c.execute(f"INSERT INTO {table} ({cols}) VALUES ({qs})", vals).lastrowid

    def update(self, table: str, key: str, key_val, row: dict) -> None:
        sets = ",".join(f"{k}=?" for k in row)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in row.values()]
        with self.tx() as c:
            c.execute(f"UPDATE {table} SET {sets} WHERE {key}=?", vals + [key_val])

    def close(self):
        with self.lock:
            self.conn.close()
