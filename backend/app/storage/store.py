"""SQLite persistence behind a small interface. One lock, one connection: simple and demo-safe."""
import json
import sqlite3
import threading
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY, name TEXT, endpoint TEXT);
CREATE TABLE IF NOT EXISTS manifests(fingerprint TEXT PRIMARY KEY, server_id TEXT, tool_name TEXT, canonical_json TEXT, captured_at REAL);
CREATE TABLE IF NOT EXISTS tools(server_id TEXT, tool_name TEXT, current_fp TEXT, updated_at REAL, PRIMARY KEY(server_id, tool_name));
CREATE TABLE IF NOT EXISTS analyses(fingerprint TEXT, stage TEXT, mode TEXT, status TEXT, risk TEXT, findings_json TEXT,
  latency_ms REAL, version TEXT, created_at REAL, PRIMARY KEY(fingerprint, stage));
CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT, tool_name TEXT, fingerprint TEXT,
  decision TEXT, confirmed INTEGER, approved_at REAL, policy_version TEXT, analysis_mode TEXT, status TEXT, approved_by TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, event_type TEXT, server_id TEXT, tool_name TEXT,
  previous_fingerprint TEXT, current_fingerprint TEXT, changed_fields TEXT, reason TEXT, prev_event_hash TEXT, hash TEXT);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript(_SCHEMA)
            try:  # databases created before approver identity existed
                self.db.execute("ALTER TABLE approvals ADD COLUMN approved_by TEXT")
            except sqlite3.OperationalError:
                pass

    def q(self, sql: str, *a) -> list[sqlite3.Row]:
        with self.lock:
            return self.db.execute(sql, a).fetchall()

    def x(self, sql: str, *a) -> None:
        with self.lock:
            self.db.execute(sql, a)
            self.db.commit()

    def reset(self):
        with self.lock:
            for t in ("servers", "manifests", "tools", "analyses", "approvals", "audit"):
                self.db.execute(f"DELETE FROM {t}")
            self.db.commit()

    # servers / manifests
    def upsert_server(self, id: str, name: str, endpoint: str):
        self.x("INSERT OR REPLACE INTO servers VALUES(?,?,?)", id, name, endpoint)

    def servers(self):
        return self.q("SELECT * FROM servers ORDER BY id")

    def server(self, id: str):
        r = self.q("SELECT * FROM servers WHERE id=?", id)
        return r[0] if r else None

    def save_manifest(self, sid: str, tool: str, fp: str, canonical_json: str):
        self.x("INSERT OR IGNORE INTO manifests VALUES(?,?,?,?,?)", fp, sid, tool, canonical_json, time.time())
        self.x("INSERT OR REPLACE INTO tools VALUES(?,?,?,?)", sid, tool, fp, time.time())

    def manifest(self, fp: str) -> dict | None:
        r = self.q("SELECT canonical_json FROM manifests WHERE fingerprint=?", fp)
        return json.loads(r[0][0]) if r else None

    def tools(self):
        return self.q("SELECT * FROM tools ORDER BY server_id, tool_name")

    def current_fp(self, sid: str, tool: str) -> str | None:
        r = self.q("SELECT current_fp FROM tools WHERE server_id=? AND tool_name=?", sid, tool)
        return r[0][0] if r else None

    # analyses
    def save_analysis(self, fp, stage, mode, status, risk, findings: list[dict], latency_ms, version):
        self.x("INSERT OR REPLACE INTO analyses VALUES(?,?,?,?,?,?,?,?,?)", fp, stage, mode, status, risk,
               json.dumps(findings), latency_ms, version, time.time())

    def analysis(self, fp: str, stage: str):
        r = self.q("SELECT * FROM analyses WHERE fingerprint=? AND stage=?", fp, stage)
        return r[0] if r else None

    # approvals
    def add_approval(self, sid, tool, fp, decision, confirmed, policy_version, analysis_mode, approved_by=None):
        with self.lock:
            self.db.execute("UPDATE approvals SET status='superseded' WHERE server_id=? AND tool_name=? AND status IN('active','stale')", (sid, tool))
            self.db.execute("INSERT INTO approvals(server_id,tool_name,fingerprint,decision,confirmed,approved_at,policy_version,analysis_mode,status,approved_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (sid, tool, fp, decision, int(confirmed), time.time(), policy_version, analysis_mode,
                             "active" if decision == "approved" else "denied", approved_by))
            self.db.commit()

    def active_approval(self, sid: str, tool: str):
        r = self.q("SELECT * FROM approvals WHERE server_id=? AND tool_name=? AND decision='approved' AND status IN('active','stale') ORDER BY id DESC LIMIT 1", sid, tool)
        return r[0] if r else None

    def mark_stale(self, approval_id: int):
        self.x("UPDATE approvals SET status='stale' WHERE id=?", approval_id)

    def is_denied(self, sid: str, tool: str, fp: str) -> bool:
        return bool(self.q("SELECT 1 FROM approvals WHERE server_id=? AND tool_name=? AND fingerprint=? AND decision='denied'", sid, tool, fp))

    def approved_pairs(self) -> list[tuple[str, str]]:
        return [(r[0], r[1]) for r in self.q("SELECT DISTINCT server_id, tool_name FROM approvals WHERE decision='approved' AND status IN('active','stale')")]
