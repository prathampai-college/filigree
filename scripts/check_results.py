"""Re-score every frozen set with the current scanner and fail if any committed headline number moved.
CI runs this, so a rule change cannot silently invalidate a figure quoted in README / docs/RESULTS.md.
Scanner only (no LLM, no network). MCPTox is checked only when fixtures/external/mcptox_corpus.json exists (gitignored).
Usage: uv run --project backend python scripts/check_results.py      -> exit 1 and the moved numbers on any difference
After an intended rule change: re-run the evaluation scripts, commit the new results files, update docs/RESULTS.md.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend")]
from app.manifest.canonicalize import build_manifest  # noqa: E402
from app.policy.evaluate import eligibility  # noqa: E402
from app.scanner.rules import scan  # noqa: E402

EV = ROOT / "fixtures" / "evaluation"
CORPUS = ROOT / "fixtures" / "external" / "mcptox_corpus.json"
pct = lambda n, d: None if d == 0 else round(100 * n / d, 1)
KEYS = ("poisoned", "benign", "recall_blocked_pct", "recall_flagged_pct", "benign_acceptance_pct", "benign_blocked_pct",
        "missed", "not_blocked", "blocked_false_positives", "false_positives")


def score(cases, real=False):
    rows = []
    for c in cases:
        m = build_manifest(c["tool"], f"real-{c.get('server', 'x')}", c.get("instructions")) if real else build_manifest(c["tool"], "srv-eval")
        rows.append((c, eligibility(scan(m, known_tools=set(c.get("tool_names", []))) if real else scan(m), True).action))
    pos = [(c, a) for c, a in rows if c["label"] == "poisoned"]
    neg = [(c, a) for c, a in rows if c["label"] == "benign"]
    return {"poisoned": len(pos), "benign": len(neg),
            "recall_blocked_pct": pct(sum(a == "block" for _, a in pos), len(pos)),
            "recall_flagged_pct": pct(sum(a != "allow" for _, a in pos), len(pos)),
            "benign_acceptance_pct": pct(sum(a == "allow" for _, a in neg), len(neg)),
            "benign_blocked_pct": pct(sum(a == "block" for _, a in neg), len(neg)),
            "missed": [c["id"] for c, a in pos if a == "allow"], "not_blocked": [c["id"] for c, a in pos if a != "block"],
            "blocked_false_positives": [c["id"] for c, a in neg if a == "block"],
            "false_positives": [c["id"] for c, a in neg if a != "allow"]}


def load(name):
    return json.loads((EV / name).read_text(encoding="utf-8"))


def split(cases, half):  # same split as evaluate_real.py --split: servers sorted by name, even index = dev
    servers = sorted({c["server"] for c in cases})
    dev = {s for i, s in enumerate(servers) if i % 2 == 0}
    return [c for c in cases if (c["server"] in dev) == (half == "dev")]


v1 = [c for s in ("authored.json", "public_heldout.json", "evasive.json") for c in load(s) if c["label"] != "rug_pull"]
r1 = load("results.json")["scanner"]  # v1 file (also served to the Evaluation page) keeps id lists outside the per-set stats
checks = [("v1", score(v1), {**r1["ALL"], "missed": r1["missed"], "false_positives": r1["false_positives"]})]
checks += [(s, score(load(f"{s}.json")), load(f"results_{s}_steer_rule.json")) for s in ("v2", "v3", "v4")]
checks.append(("real_benign", score(load("real_benign.json"), real=True), load("results_real_benign_steer_rule.json")))
if CORPUS.exists():
    mcptox = json.loads(CORPUS.read_text(encoding="utf-8"))
    checks += [(f"mcptox_{h}", score(split(mcptox, h), real=True), load(f"results_mcptox_corpus_{h}_steer_rules.json")) for h in ("dev", "test")]
else:
    print("mcptox: skipped (fixtures/external/mcptox_corpus.json not present; see docs/INDEPENDENT-EVAL.md)")

failed = 0
for name, now, committed in checks:
    moved = {k: {"added": sorted(set(now[k]) - set(committed[k])), "removed": sorted(set(committed[k]) - set(now[k]))}
             if isinstance(now[k], list) else [committed[k], now[k]] for k in KEYS if k in committed and committed[k] != now[k]}
    failed += bool(moved)
    print(f"{name}: {'MOVED ' + json.dumps(moved) if moved else 'ok'} "
          f"(blocked {now['recall_blocked_pct']}%, benign blocked {now['benign_blocked_pct']}%)")
sys.exit(1 if failed else 0)
