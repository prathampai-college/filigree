"""Evaluation runner: scanner-only / LLM-only / combined on frozen sets (PRD §15.2).
LLM columns run only when ANALYZER_API_KEY is set; otherwise they are reported as "not run" (never invented).
Usage: uv run --project backend python scripts/evaluate.py
"""
import asyncio
import hashlib
import json
import os
import statistics
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]
from app.analyzer.impl import LiveAnalyzer, resolve_key  # noqa: E402
from app.envfile import load_dotenv  # noqa: E402
from app.manifest.canonicalize import build_manifest, fingerprint  # noqa: E402
from app.policy.evaluate import eligibility, merge_findings  # noqa: E402
from app.scanner.rules import scan  # noqa: E402

EV = ROOT / "fixtures" / "evaluation"
SETS = ["authored.json", "public_heldout.json", "evasive.json"]


def pct(n, d): return None if d == 0 else round(100 * n / d, 1)
def p(xs, q): return None if not xs else round(sorted(xs)[min(len(xs) - 1, int(q * len(xs)))], 2)


async def main():
    text = "".join((EV / s).read_text(encoding="utf-8") for s in SETS)
    frozen = (EV / "FROZEN.sha256").read_text().strip()
    intact = hashlib.sha256(text.encode("utf-8")).hexdigest() == frozen
    load_dotenv()
    live = LiveAnalyzer(httpx.AsyncClient()) if resolve_key(os.environ.get("ANALYZER_PROVIDER")) else None
    if live:
        print(f"live analyzer: {live.provider} / {live.model}")
    rows, lat_s, lat_l, unavailable = [], [], [], 0
    for sname in SETS:
        for c in json.loads((EV / sname).read_text(encoding="utf-8")):
            if c["label"] == "rug_pull":
                continue
            m = build_manifest(c["tool"], "srv-eval")
            t0 = time.perf_counter()
            sf = scan(m)
            lat_s.append((time.perf_counter() - t0) * 1000)
            row = {"id": c["id"], "set": sname, "label": c["label"], "scanner": eligibility(sf, True).action}
            if live:
                res = await live.analyze(m, "eval", sf)
                unavailable += res.status != "complete"
                if res.status == "complete":
                    lat_l.append(res.latency_ms)
                else:
                    print("analyzer unavailable:", c["id"], res.note)
                row["llm"] = eligibility(res.findings, res.status == "complete").action
                row["combined"] = eligibility(merge_findings(sf, res.findings), res.status == "complete").action
            rows.append(row)

    def stats(cfg):
        out = {}
        for sname in SETS + ["ALL"]:
            rs = [r for r in rows if (sname == "ALL" or r["set"] == sname) and cfg in r]
            pos, neg = [r for r in rs if r["label"] == "poisoned"], [r for r in rs if r["label"] == "benign"]
            out[sname] = {"poisoned": len(pos), "benign": len(neg),
                          "recall_blocked_pct": pct(sum(r[cfg] == "block" for r in pos), len(pos)),
                          "recall_flagged_pct": pct(sum(r[cfg] != "allow" for r in pos), len(pos)),
                          "benign_acceptance_pct": pct(sum(r[cfg] == "allow" for r in neg), len(neg)),
                          "false_positive_pct": pct(sum(r[cfg] != "allow" for r in neg), len(neg))}
        out["missed"] = [r["id"] for r in rows if r["label"] == "poisoned" and cfg in r and r[cfg] == "allow"]
        out["false_positives"] = [r["id"] for r in rows if r["label"] == "benign" and cfg in r and r[cfg] != "allow"]
        return out

    # integrity mechanism (deterministic)
    pulls = [c for c in json.loads((EV / "authored.json").read_text(encoding="utf-8")) if c["label"] == "rug_pull"]
    drift = sum(fingerprint(build_manifest(c["tool"], "s")) != fingerprint(build_manifest(c["after"], "s")) for c in pulls)
    benign = [c["tool"] for c in json.loads((EV / "authored.json").read_text(encoding="utf-8")) if c["label"] == "benign"]
    false_drift = 0
    for t in benign:  # same content, different key order / inter-token whitespace -> must not drift
        reordered = json.loads(json.dumps(dict(reversed(list(t.items()))), indent=3))
        false_drift += fingerprint(build_manifest(t, "s")) != fingerprint(build_manifest(reordered, "s"))

    result = {"sets_frozen_intact": intact, "frozen_sha256": frozen, "n_scored": len(rows),
              "scanner": stats("scanner"), "llm": stats("llm") if live else "not run (no API key)",
              "combined": stats("combined") if live else "not run (no API key)",
              "drift_recall_pct": pct(drift, len(pulls)), "drift_cases": len(pulls),
              "false_drift": false_drift, "false_drift_cases": len(benign),
              "scanner_latency_ms": {"p50": p(lat_s, .5), "p95": p(lat_s, .95)},
              "llm_unavailable": unavailable if live else "not run", "llm_latency_ms": {"p50": p(lat_l, .5), "p95": p(lat_l, .95)} if lat_l else "not run",
              "note": "Authored sets were written by the team; public samples are illustrative, modeled on published attack classes (see fixtures/evaluation/SOURCES.md). "
                      "Scanner rules were tuned once after seeing v1 misses, so these numbers are in-sample (see v3 for unseen)."}
    (EV / "results.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("sets_frozen_intact", "drift_recall_pct", "false_drift", "scanner_latency_ms")}))
    for sname, s in result["scanner"].items():
        print(sname, s)


asyncio.run(main())
