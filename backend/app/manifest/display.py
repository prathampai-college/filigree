"""UI-only renderers. They never touch the hash."""
from .invisible import decode_hidden, invisible_chars


def escape_for_display(text: str) -> str:
    hidden = {i for i, _ in invisible_chars(text)}
    return "".join(f"[U+{ord(c):04X}]" if i in hidden else c for i, c in enumerate(text))


def human_rendering(text: str, limit: int = 160) -> str:
    """Simulated typical client: invisible characters render as nothing, long text is truncated."""
    hidden = {i for i, _ in invisible_chars(text)}
    shown = "".join(c for i, c in enumerate(text) if i not in hidden)
    return shown if len(shown) <= limit else shown[:limit].rstrip() + "…"


def hidden_stats(text: str) -> tuple[int, str | None]:
    return len(invisible_chars(text)), decode_hidden(text) or None
