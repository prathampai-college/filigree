# Results: every number, its file, and how much to trust it

All files are in `fixtures/evaluation/`. Every figure on this page is copied from the file named next to it; nothing here is new.
Status says how far the current rules were shaped by that set: **independent** (written by other people), **held out** (not used to
build the rule that is measured), **unseen** (frozen before a rule change, scored once), **in-sample** (rules were changed after
looking at its misses, so it flatters us).

**Kept honest by CI**: `scripts/check_results.py` re-scores every frozen set with the current scanner and fails the build if any
number or listed case id below differs from its committed file (MCPTox is checked only where its files are present, see below).
A rule change therefore has to come with new result files and an update of this page.

## Headline: independent benchmark (MCPTox)
485 real poisoned tool descriptions + 362 clean tools from 45 real servers (Wang et al., arXiv 2508.14925). Corpus not committed
(no license), how to rebuild it: [`INDEPENDENT-EVAL.md`](INDEPENDENT-EVAL.md).

| Measurement | Status | Poisoned blocked | Poisoned flagged | Clean accepted | Clean blocked | File |
|---|---|---|---|---|---|---|
| Scanner, first run, all 485 + 362 | independent, run once before any MCPTox rule | 14.8% (72/485) | 99.2% (77.5% excluding the cross-tool rule) | 86.5% | 1.4% (5) | `results_mcptox_corpus_scanner.json` |
| Scanner, **held-out half** (200 + 146), with the steering rule | **independent, held out, scored once** | **73.0%** (11.0% before the rule) | 99.0% | 91.1% | **1.4%** (2) | `results_mcptox_corpus_test_steer_rules.json` (`..._test_before_steer.json`) |
| Scanner, dev half (285 + 216) | rule built on it | 68.4% (17.5% before) | 99.3% | 83.3% | 1.4% (3) | `results_mcptox_corpus_dev_steer_rules.json` |
| Scanner vs scanner + LLM, seeded sample of the held-out half (40 + 20, gpt-oss-120b) | independent, held out; **small N** | 70.0% -> **87.5%** | 97.5% -> 100% | 95.0% -> 90.0% | 0% -> 5.0% (1 of 20) | `results_mcptox_corpus_llm_sample.json` |

Quote the held-out 73.0%, not the 70.3% of both halves together. `results_mcptox_corpus_test_llm.json` is the scanner-only score
written by the same command that ran the LLM sample; it equals the held-out row.
Rerun: `uv run --project backend python scripts/evaluate_real.py fixtures/external/mcptox_corpus.json <label> --split test`.

## False positives on real servers
| Set | Status | Clean accepted | Clean blocked | File |
|---|---|---|---|---|
| 52 tools from 7 official MCP servers (assumed benign) | in-sample for the two 2026-10-07 fixes | 71.2% -> **96.2%** | 1.9% -> **0%** | `results_real_benign_{before,after}_rules.json`, current: `results_real_benign_steer_rule.json` |

Remaining flags (review, not block): filesystem `read_file`, `create_directory`, one low URL finding. Details: [`REAL-WORLD-SCAN.md`](REAL-WORLD-SCAN.md).
Rerun: `uv run --project backend python scripts/evaluate_real.py real_benign.json <label>`.

## Team-authored sets
Written by the team, so they share our blind spots; read the unseen rows as the fairer ones.

| Set | Status | Poisoned blocked / flagged | Clean accepted | Clean blocked | File |
|---|---|---|---|---|---|
| v4 (12 + 12), old rules | **unseen** (frozen before the 2026-10-07 change) | 66.7% / 75.0% | 66.7% | 25.0% (3) | `results_v4_baseline.json` |
| v4, current rules | in-sample | 66.7% / 75.0% | 66.7% | 0% | `results_v4_steer_rule.json` |
| v3 (12 + 10) | was unseen, scored once; seen since 2026-10-07 | 58.3% / 83.3% | 90.0% | 0% (current) | `results_v3_once.json`, current: `results_v3_steer_rule.json` |
| v2 (20 + 20) before / after tuning | unbiased / in-sample | 45.0% / 50.0% -> 95.0% / 100% | 65.0% -> 100% | 0% (current) | `results_v2_before_rules.json`, current: `results_v2_steer_rule.json` |
| v1 (32 + 15) before / after tuning | unbiased / in-sample | 62.5% / 75.0% -> 78.1% / 90.6% | 86.7% -> 100% | 0% (current) | `results_v1_pretuning.json`, current: `results.json` |

Rerun: `uv run --project backend python scripts/evaluate.py` (v1, writes `results.json`, which the UI's Evaluation page reads) and
`SET=v4 NO_LLM=1 uv run --project backend python scripts/evaluate_v2.py <label>` (v2, v3, v4).

LLM on team sets (Groq `openai/gpt-oss-120b`, model shown the scanner findings, so an upper bound):
- v1, 47 cases (`results.json`, keys `llm` and `combined`): 100% blocked, 100% clean accepted, p50 5.9 s / p95 8.6 s.
- v3, 22 cases (`results_v3_with_llm.json`): 100% blocked, 80% clean accepted (false positives: `read_config`, "Silently queue notifications").

## Mechanism (not detection)
From `results.json`: rug-pull drift detected 5/5 (100%), false drift 0/15 (same content, reordered keys and whitespace).
Scanner latency p50 0.14 ms / p95 0.20 ms on the last v1 run (0.08 / 0.13 ms in `results_v1_pretuning.json`).
End-to-end checks with real software: `scripts/sdk_client_check.py` (official MCP SDK client against the gateway, in CI) and
`scripts/real_gateway_check.py` (official filesystem server behind `filigree run`, 7/7 on 2026-10-07, needs `npx`, not in CI).

## Frozen inputs
Each set has a `FROZEN_*.sha256` (v1: `FROZEN.sha256`); `backend/tests/test_frozen_sets.py` fails if a set file changes.
Result files record `set_frozen_intact: true` when they were produced.
