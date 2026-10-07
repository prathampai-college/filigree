"""Scanner-only evaluation on corpora of REAL tool definitions (not team-authored).

real_benign.json: 52 definitions from 7 official MCP servers, assumed benign (read by the scanner, not audited line by line).
Any other corpus: a JSON list of {"id", "label": "poisoned"|"benign", "tool", optional "server", "instructions", "tool_names"}.
Usage: uv run --project backend python scripts/evaluate_real.py <corpus.json> <label>   -> fixtures/evaluation/results_<corpus>_<label>.json
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend")]
from app.manifest.canonicalize import build_manifest  # noqa: E402
from app.policy.evaluate import eligibility  # noqa: E402
from app.scanner.rules import scan  # noqa: E402

EV = ROOT / "fixtures" / "evaluation"
pct = lambda n, d: None if d == 0 else round(100 * n / d, 1)

corpus, label = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "run"
raw = (EV / corpus).read_text(encoding="utf-8")
frozen = EV / f"FROZEN_{Path(corpus).stem}.sha256"
intact = frozen.exists() and hashlib.sha256(raw.encode("utf-8")).hexdigest() == frozen.read_text().strip()
rows = []
for c in json.loads(raw):
    m = build_manifest(c["tool"], f"real-{c.get('server', 'x')}", c.get("instructions"))
    rows.append((c, eligibility(scan(m, known_tools=set(c.get("tool_names", []))), True).action))
pos = [(c, a) for c, a in rows if c["label"] == "poisoned"]
neg = [(c, a) for c, a in rows if c["label"] == "benign"]
res = {"corpus": corpus, "label": label, "set_frozen_intact": intact, "poisoned": len(pos), "benign": len(neg),
       "recall_blocked_pct": pct(sum(a == "block" for _, a in pos), len(pos)),
       "recall_flagged_pct": pct(sum(a != "allow" for _, a in pos), len(pos)),
       "benign_acceptance_pct": pct(sum(a == "allow" for _, a in neg), len(neg)),
       "benign_blocked_pct": pct(sum(a == "block" for _, a in neg), len(neg)),
       "missed": [c["id"] for c, a in pos if a == "allow"], "not_blocked": [c["id"] for c, a in pos if a != "block"],
       "blocked_false_positives": [c["id"] for c, a in neg if a == "block"],
       "review_false_positives": [c["id"] for c, a in neg if a == "review"]}
(EV / f"results_{Path(corpus).stem}_{label}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
print(json.dumps(res))
