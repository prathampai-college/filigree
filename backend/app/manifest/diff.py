"""Field-level diff between two manifests, with explicit hidden-character entries."""
import difflib
from typing import Any

from .invisible import invisible_chars


def _walk(a: Any, b: Any, path: str, out: list[dict]):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(a.keys() | b.keys()):
            _walk(a.get(k), b.get(k), f"{path}.{k}" if path else k, out)
    elif a != b:
        entry = {"field": path, "before": a, "after": b}
        if isinstance(a, str) and isinstance(b, str):
            entry["lines"] = list(difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=1))
            ha, hb = len(invisible_chars(a)), len(invisible_chars(b))
            if ha != hb:
                entry["hidden_chars"] = {"before": ha, "after": hb}
        out.append(entry)


def diff_manifests(old: dict, new: dict) -> list[dict]:
    out: list[dict] = []
    _walk(old, new, "", out)
    return out


def changed_fields(old: dict, new: dict) -> list[str]:
    return [d["field"] for d in diff_manifests(old, new)]
