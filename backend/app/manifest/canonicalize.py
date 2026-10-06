"""Canonical manifest + fingerprint (D-03, D-04, D-17, D-21). String contents are kept verbatim."""
import hashlib
import json
from typing import Any

# Security-relevant tool fields. Icons/display-only fields are excluded (D-03).
TOOL_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")


def loads_strict(raw: str | bytes) -> Any:
    """json.loads that rejects duplicate keys and NaN/Infinity."""
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError(f"duplicate JSON key: {k!r}")
            d[k] = v
        return d

    def bad(c):
        raise ValueError(f"non-finite number: {c}")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)


def build_manifest(tool: dict, server_id: str, server_instructions: str | None = None) -> dict:
    return {
        "manifest_version": 1,
        "server": {"id": server_id, "instructions": server_instructions},
        "tool": {k: tool[k] for k in TOOL_FIELDS if k in tool},
    }


def canonical_bytes(manifest: dict) -> bytes:
    # allow_nan=False rejects NaN; encode() rejects lone surrogates.
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def fingerprint(manifest: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(manifest)).hexdigest()


def registry_view(manifest: dict) -> dict:
    """What the agent registry receives: parsed back from the canonical bytes (representation invariant)."""
    return loads_strict(canonical_bytes(manifest))
