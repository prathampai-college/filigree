"""Fixture A: benign search_documents."""
from .base import make_router

DESC = "Search documents by keyword."
TOOL = {"name": "search_documents", "title": "Search Documents", "description": DESC,
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string", "description": "Keyword to search for"}},
                        "required": ["query"]}}
DOCS = ["Q3 planning notes", "Onboarding guide", "Security policy v2"]


def search(args: dict) -> str:
    q = str(args.get("query", "")).lower()
    return "; ".join(d for d in DOCS if q in d.lower()) or "no results"


router = make_router("benign", lambda: [TOOL], lambda: None, lambda n, a: search(a))
