"""Scanner-only evaluation on the v2 sets (frozen before rules were changed for v1 misses). Writes results_v2_<label>.json.
Usage: uv run --project backend python scripts/evaluate_v2.py [label]
"""
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]
from app.manifest.canonicalize import build_manifest  # noqa: E402
from app.policy.evaluate import eligibility  # noqa: E402
from app.scanner.rules import scan  # noqa: E402
from app.analyzer.impl import LiveAnalyzer, resolve_key  # noqa: E402
from app.envfile import load_dotenv  # noqa: E402
from app.policy.evaluate import merge_findings  # noqa: E402
import httpx  # noqa: E402

EV = ROOT / "fixtures" / "evaluation"
pct = lambda n, d: round(100 * n / d, 1)
raw = (EV / f"{os.environ.get('SET', 'v2')}.json").read_text(encoding="utf-8")
intact = hashlib.sha256(raw.encode("utf-8")).hexdigest() == (EV / f"FROZEN_{os.environ.get('SET', 'v2')}.sha256").read_text().strip()
load_dotenv()
cases = json.loads(raw)
mans = [build_manifest(c["tool"], "srv-eval") for c in cases]
sfs = [scan(m) for m in mans]
rows = [(c, eligibility(sf, True).action) for c, sf in zip(cases, sfs)]
llm_rows, comb_rows, unavailable = [], [], 0
if resolve_key(os.environ.get("ANALYZER_PROVIDER")):
    live = LiveAnalyzer(httpx.AsyncClient())

    async def run():
        return [await live.analyze(m, "eval", sf) for m, sf in zip(mans, sfs)]
    for c, sf, r in zip(cases, sfs, asyncio.run(run())):
        unavailable += r.status != "complete"
        llm_rows.append((c, eligibility(r.findings, r.status == "complete").action))
        comb_rows.append((c, eligibility(merge_findings(sf, r.findings), r.status == "complete").action))
    print("live analyzer:", live.provider, live.model, "unavailable:", unavailable)


def stats(rs):
    pos = [(c, a) for c, a in rs if c["label"] == "poisoned"]
    neg = [(c, a) for c, a in rs if c["label"] == "benign"]
    return {"poisoned": len(pos), "benign": len(neg),
            "recall_blocked_pct": pct(sum(a == "block" for _, a in pos), len(pos)),
            "recall_flagged_pct": pct(sum(a != "allow" for _, a in pos), len(pos)),
            "benign_acceptance_pct": pct(sum(a == "allow" for _, a in neg), len(neg)),
            "not_blocked": [c["id"] for c, a in pos if a != "block"], "missed": [c["id"] for c, a in pos if a == "allow"],
            "false_positives": [c["id"] for c, a in neg if a != "allow"]}


pos = [(c, a) for c, a in rows if c["label"] == "poisoned"]
neg = [(c, a) for c, a in rows if c["label"] == "benign"]
res = {"label": sys.argv[1] if len(sys.argv) > 1 else "run", "set_frozen_intact": intact,
       "poisoned": len(pos), "benign": len(neg),
       "recall_blocked_pct": pct(sum(a == "block" for _, a in pos), len(pos)),
       "recall_flagged_pct": pct(sum(a != "allow" for _, a in pos), len(pos)),
       "benign_acceptance_pct": pct(sum(a == "allow" for _, a in neg), len(neg)),
       "missed": [c["id"] for c, a in pos if a == "allow"], "not_blocked": [c["id"] for c, a in pos if a != "block"],
       "false_positives": [c["id"] for c, a in neg if a != "allow"]}
if llm_rows:
    res.update(llm=stats(llm_rows), combined=stats(comb_rows), llm_unavailable=unavailable)
(EV / f"results_{os.environ.get('SET', 'v2')}_{res['label']}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
print(json.dumps(res))
