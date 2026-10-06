import hashlib
from pathlib import Path

EV = Path(__file__).resolve().parents[2] / "fixtures" / "evaluation"


def _sha(*names):
    return hashlib.sha256("".join((EV / n).read_text(encoding="utf-8") for n in names).encode("utf-8")).hexdigest()


def test_frozen_evaluation_sets_unchanged():
    assert _sha("authored.json", "public_heldout.json", "evasive.json") == (EV / "FROZEN.sha256").read_text().strip()
    assert _sha("v2.json") == (EV / "FROZEN_v2.sha256").read_text().strip()
    assert _sha("v3.json") == (EV / "FROZEN_v3.sha256").read_text().strip()
