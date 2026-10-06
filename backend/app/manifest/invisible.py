"""Detect and decode invisible/control characters. Display + scanner only; never used to alter hashed content (D-04)."""
import unicodedata

_EXPLICIT = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x180E, 0x034F}
_VS = [(0xFE00, 0xFE0F), (0xE0100, 0xE01EF)]
_ZWJ, _ZWNJ = 0x200D, 0x200C


def _is_vs(cp: int) -> bool:
    return any(a <= cp <= b for a, b in _VS)


def _legit_joiner(text: str, i: int) -> bool:
    """ZWJ/ZWNJ/VS16 inside emoji or non-Latin scripts are normal text, not payload."""
    cp = ord(text[i])
    prev = unicodedata.category(text[i - 1]) if i > 0 else ""
    nxt = unicodedata.category(text[i + 1]) if i + 1 < len(text) else ""
    if cp in (_ZWJ, 0xFE0F):
        return prev in ("So", "Sk") and (cp == 0xFE0F or nxt in ("So", "Sk"))
    if cp == _ZWNJ:
        return (i > 0 and ord(text[i - 1]) > 0x24F and prev[0] in "LM"
                and i + 1 < len(text) and ord(text[i + 1]) > 0x24F and nxt[0] in "LM")
    return False


def invisible_chars(text: str) -> list[tuple[int, int]]:
    """[(index, codepoint)] of hidden characters."""
    out = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        hidden = unicodedata.category(ch) in ("Cf", "Co", "Cn") or cp in _EXPLICIT or _is_vs(cp)
        if hidden and not (ch in "\r\n\t") and not _legit_joiner(text, i):
            out.append((i, cp))
    return out


def decode_hidden(text: str) -> str:
    """Decode tag-character ASCII and variation-selector byte runs (len>=2) hidden in text."""
    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    vs, run = [], []
    for c in text + "\0":
        cp = ord(c)
        if _is_vs(cp):
            run.append(cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16)
        else:
            if len(run) >= 2:
                vs.append(bytes(run).decode("utf-8", "replace"))
            run = []
    return " ".join(x for x in (tags, *vs) if x)
