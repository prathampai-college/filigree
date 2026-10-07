"""Scanner-only evaluation on corpora of REAL tool definitions (not team-authored).

real_benign.json: 52 definitions from 7 official MCP servers, assumed benign (read by the scanner, not audited line by line).
Any other corpus: a JSON list of {"id", "label": "poisoned"|"benign", "tool", optional "server", "instructions", "tool_names"}.
Usage: uv run --project backend python scripts/evaluate_real.py <corpus.json> <label> [--llm-sample N_POISONED N_BENIGN]
--llm-sample also runs the live LLM analyzer on a seeded random sample (seed 0; ~12 s per call to stay under free-tier limits)
and reports scanner vs scanner+LLM on that same sample.
Original usage: <corpus.json> <label>   -> fixtures/evaluation/results_<corpus>_<label>.json
"""
import asyncio
import hashlib
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend")]
from app.manifest.canonicalize import build_manifest  # noqa: E402
from app.policy.evaluate import eligibility  # noqa: E402
from app.scanner.rules import scan  # noqa: E402
from app.analyzer.impl import LiveAnalyzer, resolve_key  # noqa: E402
from app.envfile import load_dotenv  # noqa: E402
from app.policy.evaluate import merge_findings  # noqa: E402
import httpx  # noqa: E402

EV = ROOT / "fixtures" / "evaluation"
pct = lambda n, d: None if d == 0 else round(100 * n / d, 1)

corpus, label = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "run"
path = Path(corpus) if Path(corpus).is_file() else EV / corpus  # a path (e.g. fixtures/external/...) or a name in fixtures/evaluation
raw = path.read_text(encoding="utf-8")
frozen = path.parent / f"FROZEN_{path.stem}.sha256"
intact = frozen.exists() and hashlib.sha256(raw.encode("utf-8")).hexdigest() == frozen.read_text().strip()
rows = []
split = sys.argv[sys.argv.index("--split") + 1] if "--split" in sys.argv else None  # dev/test: servers sorted by name, even index = dev
all_cases = json.loads(raw)
if split:
    servers = sorted({c["server"] for c in all_cases})
    dev = {s for i, s in enumerate(servers) if i % 2 == 0}
    all_cases = [c for c in all_cases if (c["server"] in dev) == (split == "dev")]
    label = f"{split}_{label}"
for c in all_cases:
    m = build_manifest(c["tool"], f"real-{c.get('server', 'x')}", c.get("instructions"))
    rows.append((c, eligibility(scan(m, known_tools=set(c.get("tool_names", []))), True).action))
pos = [(c, a) for c, a in rows if c["label"] == "poisoned"]
neg = [(c, a) for c, a in rows if c["label"] == "benign"]
by = {}
for key in ("paradigm", "risk"):  # recall per attack template / risk category, when the corpus labels them
    for c, a in pos:
        if c.get(key):
            g = by.setdefault(key, {}).setdefault(c[key], {"n": 0, "blocked": 0, "flagged": 0})
            g["n"] += 1; g["blocked"] += a == "block"; g["flagged"] += a != "allow"
res = {"corpus": path.name, "label": label, "set_frozen_intact": intact, "poisoned": len(pos), "benign": len(neg),
       "recall_blocked_pct": pct(sum(a == "block" for _, a in pos), len(pos)),
       "recall_flagged_pct": pct(sum(a != "allow" for _, a in pos), len(pos)),
       "benign_acceptance_pct": pct(sum(a == "allow" for _, a in neg), len(neg)),
       "benign_blocked_pct": pct(sum(a == "block" for _, a in neg), len(neg)),
       "missed": [c["id"] for c, a in pos if a == "allow"], "not_blocked": [c["id"] for c, a in pos if a != "block"],
       "blocked_false_positives": [c["id"] for c, a in neg if a == "block"],
       "review_false_positives": [c["id"] for c, a in neg if a == "review"], "poisoned_by": by}
(EV / f"results_{path.stem}_{label}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
print(json.dumps(res))


async def llm_sample(n_pos: int, n_neg: int):
    load_dotenv()
    if not resolve_key(os.environ.get("ANALYZER_PROVIDER")):
        print("no analyzer key: LLM sample not run")
        return
    cases = json.loads(raw)
    rng = random.Random(0)
    pick = rng.sample([c for c in cases if c["label"] == "poisoned"], n_pos) + rng.sample([c for c in cases if c["label"] == "benign"], n_neg)
    live, rows, unavailable = LiveAnalyzer(httpx.AsyncClient()), [], 0
    for i, c in enumerate(pick):
        m = build_manifest(c["tool"], f"real-{c.get('server', 'x')}", c.get("instructions"))
        sf = scan(m, known_tools=set(c.get("tool_names", [])))
        r = await live.analyze(m, "eval", sf)
        unavailable += r.status != "complete"
        rows.append((c, eligibility(sf, True).action, eligibility(merge_findings(sf, r.findings), r.status == "complete").action))
        print(i + 1, len(pick), c["id"], rows[-1][1], rows[-1][2], flush=True)
        await asyncio.sleep(12)

    def st(ix):
        p_, n_ = [r for r in rows if r[0]["label"] == "poisoned"], [r for r in rows if r[0]["label"] == "benign"]
        return {"recall_blocked_pct": pct(sum(r[ix] == "block" for r in p_), len(p_)), "recall_flagged_pct": pct(sum(r[ix] != "allow" for r in p_), len(p_)),
                "benign_acceptance_pct": pct(sum(r[ix] == "allow" for r in n_), len(n_)), "benign_blocked_pct": pct(sum(r[ix] == "block" for r in n_), len(n_))}
    out = {"corpus": path.name, "model": f"{live.provider}/{live.model}", "seed": 0, "poisoned": n_pos, "benign": n_neg,
           "llm_unavailable": unavailable, "scanner": st(1), "scanner_plus_llm": st(2)}
    (EV / f"results_{path.stem}_llm_sample.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out))

if "--llm-sample" in sys.argv:
    i = sys.argv.index("--llm-sample")
    asyncio.run(llm_sample(int(sys.argv[i + 1]), int(sys.argv[i + 2])))
