"""Deterministic scanner (stage 1). Findings from here can never be downgraded by the LLM."""
import base64
import re
import unicodedata
from typing import Iterator

from ..api.schemas import Finding
from ..manifest.invisible import decode_hidden, invisible_chars

_STRONG_PATH = re.compile(r"(~|\$HOME|/home/\w+)?/?\.(env|ssh|aws|netrc|npmrc|kube|gnupg|docker|git-credentials)\b|(~|\$HOME)/\.[\w-]+|\bmcp\.json\b|id_rsa|id_ed25519|/etc/(passwd|shadow)|\.pem\b", re.I)
_WEAK_SECRET = re.compile(r"\b(api[_ -]?key|token|password|secret|credentials?|private key)\b", re.I)
_ACTION = re.compile(r"\b(read|send|upload|post|forward|include|attach|exfiltrat\w*|leak|copy|append|transmit|e-?mail|mail)\b", re.I)
_URL = re.compile(r"https?://[^\s\"')>]+|\b[\w-]+(\.[\w-]+)*\.(local|com|net|io|org|xyz)\b/?\S*", re.I)
_CONCEAL = re.compile(r"\b(do not|don't|never)\s+(tell|mention|reveal|disclose|show|inform|let)\b[^.]{0,40}\b(user|human|anyone)\b|\bdo not (disclose|reveal)\b|\bwithout (telling|informing) the user\b|\b(need|needs) not (be told|know)\b|\bdoes not need to (be told|know)\b|\b(keep|kept) (it|this|that)\b[^.]{0,30}\b(between|confidential|secret|from)\b|\bwithout\b[^.]{0,40}\bnotic(e|ing)\b", re.I)
_STEER = re.compile(r"\b(must|always|required to|has to|need to|ensure)\b[^.]{0,80}\b(call|invoke|change|modify|rewrite|set|replace|override|pass|add|append|prepend|swap)\b|\b(before|prior to|when|whenever)\b[^.]{0,40}\b(using|calling|invoking|running)\b[^.]{0,120}\b(must|always|first|should|change|modify|rewrite|set)\b", re.I)
_SENTENCES = re.compile(r"(?<=[.!?])\s+|\n+")  # a steering verb counts only in the same sentence as the tool it steers
_QUIET = re.compile(r"\b(silently|quietly)\b", re.I)
_IMPERATIVE = re.compile(r"\bIMPORTANT\s*:|\bignore (all |any )?(previous|prior|above)\b|\bbefore returning\b|\byou must\b|\bdisregard\b|\bSYSTEM\s*:|\bnew instructions?\s*:|\bforget (your|all|any)\b[^.]{0,15}\b(previous|prior|guidance|instructions)\b", re.I)
_ANALYZER = re.compile(r"\b(report|return|output|say)\b[^.]{0,20}\b(no|zero|empty)\b[^.]{0,10}\bfindings?\b|\bpre-?approved\b|\balready (been )?(approved|reviewed|vetted|audited|verified)\b|\bskip (any |the )?(review|check|scan)\b|\b(security )?(scanner|analyzer|reviewer)\b", re.I)
_RISKY_PARAMS = {"path", "filepath", "file", "filename", "url", "uri", "command", "cmd", "shell"}
_PARAM_HINTS = {"url": ("page", "link", "web", "fetch", "open", "download", "site"), "uri": ("page", "link", "fetch"),
                "path": ("file", "dir", "folder", "git", "read", "repo"), "filepath": ("file",), "file": ("file", "upload", "report", "document"),
                "filename": ("file",), "command": ("command", "run", "exec", "build"), "cmd": ("command", "run"), "shell": ("shell", "run")}
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
_SPACED = re.compile(r"(?:\b\w\s{1,3}){10,}\w\b")
_IP_OR_LOCAL = re.compile(r"//\d{1,3}(\.\d{1,3}){3}|\.local\b", re.I)
_CONFUSABLES =str.maketrans({"0": "o", "1": "l", "і": "i", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "ѕ": "s", "ԁ": "d"})


def strings(node, path="") -> Iterator[tuple[str, str]]:
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from strings(v, f"{path}[{i}]")


def skeleton(name: str) -> str:
    """Comparison-only form for collision checks; never used for hashing."""
    return unicodedata.normalize("NFKC", name).casefold().translate(_CONFUSABLES).replace("-", "_")


def _within_one(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1; j += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(a) > len(b): i += 1
        elif len(a) < len(b): j += 1
        else: i += 1; j += 1
    return edits + (len(a) - i) + (len(b) - j) <= 1


def _f(cat, sev, evidence, conf="high") -> Finding:
    return Finding(source="scanner", category=cat, severity=sev, evidence=evidence[:200], confidence=conf)


def scan(manifest: dict, approved: list[tuple[str, str]] = (), known_tools: set[str] = frozenset()) -> list[Finding]:
    """approved: [(server_id, tool_name)] already approved; known_tools: other tool names for cross-tool refs."""
    out: list[Finding] = []
    tool = manifest["tool"]
    sid, name = manifest["server"]["id"], tool.get("name", "")
    texts = list(strings({"tool": tool, "server_instructions": manifest["server"].get("instructions")}))
    for path, s in texts:
        if path.endswith((".$schema", ".$id")):  # JSON Schema metadata URIs, not text the model reads (found by the real-server scan)
            continue
        hid = invisible_chars(s)
        if hid:
            dec = decode_hidden(s)
            out.append(_f("invisible_content", "high",
                          f"{path}: {len(hid)} hidden characters" + (f' decoding to "{dec}"' if dec else "")))
        for pat, cat, sev, label in ((_CONCEAL, "concealment_instruction", "high", "concealment"),
                                     (_ANALYZER, "hidden_instruction", "high", "addresses the analyzer"),
                                     (_IMPERATIVE, "hidden_instruction", "medium", "model-directed imperative")):
            m = pat.search(s)
            if m:
                out.append(_f(cat, sev, f"{path}: {label}: {m.group(0)}"))
        if m := _QUIET.search(s):  # "succeeds silently" is common in real tools: blocking only with a data-movement verb or sensitive path
            out.append(_f("concealment_instruction", "high" if _ACTION.search(s) or _STRONG_PATH.search(s) else "medium", f"{path}: concealment: {m.group(0)}"))
        m = _STRONG_PATH.search(s)
        if m:
            out.append(_f("sensitive_resource_request", "high", f"{path}: references {m.group(0)}"))
        elif (m := _WEAK_SECRET.search(s)) and path.endswith(("description", "default", "instructions")):
            risky = bool(_ACTION.search(s))
            out.append(_f("sensitive_resource_request", "medium" if risky else "low",
                          f"{path}: mentions {m.group(0)}", "medium" if risky else "low"))
        for pat, decode in ((_B64, lambda t: base64.b64decode(t + "=" * (-len(t) % 4))), (_HEX, bytes.fromhex)):
            for mm in pat.finditer(s):
                try:
                    dec = decode(mm.group(0)).decode("ascii")
                except Exception:
                    continue
                if " " in dec and dec.isprintable():
                    out.append(_f("hidden_instruction", "high", f'{path}: encoded payload decoding to "{dec}"'))
        if _SPACED.search(s):
            out.append(_f("hidden_instruction", "high", f"{path}: spaced-out letters (obfuscated text)"))
        m = _URL.search(s)
        if m and not path.startswith("tool.name"):
            sev = "high" if _ACTION.search(s) else ("medium" if _IP_OR_LOCAL.search(m.group(0)) else "low")
            out.append(_f("external_exfiltration", sev, f"{path}: destination {m.group(0)}"))
        for other in () if path.startswith("server_instructions") else known_tools - {name}:  # server text names its own tools; not a cross-tool instruction
            if re.search(rf"\b{re.escape(other)}\b", s):
                steer = path.endswith("description") and not path.startswith("server_instructions") and next(
                    (m for sen in _SENTENCES.split(s) if re.search(rf"\b{re.escape(other)}\b", sen) and (m := _STEER.search(sen))), None)
                out.append(_f("cross_tool_instruction", "high" if steer else "medium",
                              f"{path}: tells the model how to use tool {other}: {steer.group(0)}" if steer else f"{path}: references tool {other}"))
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    desc = (tool.get("description") or "").lower()
    for p in props:
        pdesc = str(props[p].get("description", "")).lower() if isinstance(props[p], dict) else ""
        hints = (p.lower(),) + _PARAM_HINTS.get(p.lower(), ())
        if p.lower() in _RISKY_PARAMS and not any(h in desc or h in name.lower() or h in pdesc for h in hints):
            out.append(_f("schema_risk", "medium", f"parameter '{p}' not mentioned in description", "medium"))
    sk = skeleton(name)
    for osid, oname in approved:
        if osid != sid and (skeleton(oname) == sk or _within_one(skeleton(oname), sk)):
            out.append(_f("name_collision", "high", f"'{name}' collides with approved '{oname}' on {osid}"))
    return out
