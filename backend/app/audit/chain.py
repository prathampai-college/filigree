"""Tamper-evident audit log: each event stores the hash of the previous event."""
import hashlib
import json
import time

from ..storage.store import Store

GENESIS = "sha256:" + "0" * 64
FIELDS = ("ts", "event_type", "server_id", "tool_name", "previous_fingerprint", "current_fingerprint", "changed_fields", "reason")


def _hash(prev: str, ev: dict) -> str:
    return "sha256:" + hashlib.sha256((prev + json.dumps(ev, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


def append(store: Store, event_type: str, server_id=None, tool_name=None, prev_fp=None, cur_fp=None,
           changed_fields=(), reason=None) -> None:
    with store.lock:  # single writer: read-last + insert must be atomic
        last = store.q("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
        prev = last[0][0] if last else GENESIS
        ev = dict(ts=round(time.time(), 3), event_type=event_type, server_id=server_id, tool_name=tool_name,
                  previous_fingerprint=prev_fp, current_fingerprint=cur_fp,
                  changed_fields=json.dumps(list(changed_fields)), reason=reason)
        store.db.execute("INSERT INTO audit(ts,event_type,server_id,tool_name,previous_fingerprint,current_fingerprint,changed_fields,reason,prev_event_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (*(ev[k] for k in FIELDS), prev, _hash(prev, ev)))
        store.db.commit()


def events(store: Store, limit: int = 200) -> list[dict]:
    rows = store.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", limit)
    return [{**dict(r), "changed_fields": json.loads(r["changed_fields"])} for r in rows]


def first_broken(store: Store) -> int | None:
    """Id of the first event whose stored hash does not match its content or its predecessor, else None."""
    prev = GENESIS
    for r in store.q("SELECT * FROM audit ORDER BY id"):
        ev = {k: r[k] for k in FIELDS}
        if r["prev_event_hash"] != prev or r["hash"] != _hash(prev, ev):
            return r["id"]
        prev = r["hash"]
    return None


def verify(store: Store) -> bool:
    return first_broken(store) is None


def export(store: Store) -> list[dict]:
    """Every event oldest-first, with hashes, so an auditor can re-verify offline."""
    rows = store.q("SELECT * FROM audit ORDER BY id")
    return [{**dict(r), "changed_fields": json.loads(r["changed_fields"])} for r in rows]
