"""Runtime checks around an approved call. Approval decides which tools; these decide what data flows through them.

taint: secrets seen in tool results (or the reference agent's file reads) may not flow into a later call's arguments.
result firewall: a result carrying model-directed instructions is withheld from the model.
"""
import json
import re

from ..manifest.invisible import decode_hidden, invisible_chars
from ..scanner.rules import _ANALYZER, _CONCEAL, _IMPERATIVE

_SECRET = re.compile(r"(?m)^\s*[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z0-9_]*\s*=\s*\S{6,}"
                     r"|\b(?:sk-[\w-]{8,}|gsk_\w{16,}|ghp_\w{20,}|AKIA[0-9A-Z]{16}|xox[bp]-[\w-]{10,})")


def _taint(ctx) -> set[str]:
    return ctx.extra.setdefault("taint", set())


def observe(ctx, text: str) -> None:
    """Remember secret-looking strings (the KEY=value line and its value) seen in data that reached the model."""
    for m in _SECRET.finditer(text or ""):
        s = m.group(0).strip()
        _taint(ctx).update(x for x in (s, s.partition("=")[2].strip()) if len(x) >= 6)


def tainted(ctx, args: dict) -> str | None:
    # ponytail: verbatim substring match; misses secrets the model re-encodes (base64, split). Add decoders if that shows up.
    blob = json.dumps(args, ensure_ascii=False)
    return next((t for t in _taint(ctx) if t in blob), None)


def result_injection(text: str) -> list[str]:
    """Instruction-like content in a tool result. File paths alone are not flagged: results legitimately mention files."""
    out = [f"{label}: {m.group(0)}" for pat, label in ((_IMPERATIVE, "model-directed imperative"), (_CONCEAL, "concealment"),
                                                         (_ANALYZER, "addresses the analyzer")) if (m := pat.search(text or ""))]
    if invisible_chars(text or ""):
        out.append(f'hidden characters decoding to "{decode_hidden(text)}"')
    return out
