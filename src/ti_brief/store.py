import json
import sqlite3
from dataclasses import asdict
from .model import Record, utcnow


class Store:
    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS records (
            key TEXT PRIMARY KEY, version TEXT NOT NULL, payload TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            misp_version TEXT, misp_uuid TEXT, reported_version TEXT, opencti_version TEXT,
            priority INTEGER NOT NULL DEFAULT 50);
          CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY, started TEXT, finished TEXT, status TEXT, details TEXT);
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(records)")}
        if "opencti_version" not in columns:
            self.db.execute("ALTER TABLE records ADD COLUMN opencti_version TEXT")
            self.db.commit()
        if "priority" not in columns:
            with self.db:
                self.db.execute("ALTER TABLE records ADD COLUMN priority INTEGER NOT NULL DEFAULT 50")
                for key, payload in self.db.execute("SELECT key,payload FROM records"):
                    self.db.execute("UPDATE records SET priority=? WHERE key=?", (json.loads(payload).get("priority", 50), key))
        self.db.execute("CREATE INDEX IF NOT EXISTS records_priority ON records(priority DESC,key)")

    def close(self):
        self.db.close()

    def upsert(self, records):
        changes = 0
        now = utcnow()
        with self.db:
            for r in records:
                previous = self.db.execute("SELECT version FROM records WHERE key=?", (r.key,)).fetchone()
                changes += previous is None or previous[0] != r.version
                self.db.execute("""INSERT INTO records(key,version,payload,first_seen,last_seen,priority)
                  VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET
                  version=excluded.version,payload=excluded.payload,last_seen=excluded.last_seen,priority=excluded.priority""",
                  (r.key, r.version, json.dumps(asdict(r)), now, now, r.priority))
        return changes

    def pending(self, column, limit):
        if column not in {"misp_version", "reported_version", "opencti_version"}:
            raise ValueError("Invalid checkpoint")
        rows = self.db.execute(f"SELECT payload FROM records WHERE {column} IS NULL OR {column} != version ORDER BY priority DESC,key LIMIT ?", (limit,)).fetchall()
        return [Record(**json.loads(row[0])) for row in rows]

    def pending_count(self, column):
        if column not in {"misp_version", "reported_version", "opencti_version"}:
            raise ValueError("Invalid checkpoint")
        return self.db.execute(f"SELECT COUNT(*) FROM records WHERE {column} IS NULL OR {column} != version").fetchone()[0]

    def checkpoint(self, record, column, event_uuid=None):
        if column not in {"misp_version", "reported_version", "opencti_version"}:
            raise ValueError("Invalid checkpoint")
        with self.db:
            self.db.execute(f"UPDATE records SET {column}=? WHERE key=? AND version=?", (record.version, record.key, record.version))
            if event_uuid:
                self.db.execute("UPDATE records SET misp_uuid=? WHERE key=?", (event_uuid, record.key))

    def seen(self, record):
        row = self.db.execute("SELECT first_seen,last_seen FROM records WHERE key=?", (record.key,)).fetchone()
        return row if row else (None, None)

    def start_run(self):
        with self.db:
            return self.db.execute("INSERT INTO runs(started,status) VALUES(?,?)", (utcnow(), "running")).lastrowid

    def finish_run(self, run_id, status, details):
        with self.db:
            self.db.execute("UPDATE runs SET finished=?,status=?,details=? WHERE id=?", (utcnow(), status, json.dumps(details), run_id))
