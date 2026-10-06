import { useEffect, useState } from 'react'
import { api } from '../api'

const f = (x: number | null | undefined) => (x == null ? '—' : `${x}%`)

export function Evaluation({ tick }: { tick: number }) {
  const [m, setM] = useState<Record<string, any>>()
  useEffect(() => { api.metrics().then(setM) }, [tick])
  if (!m) return <p>Loading…</p>
  const e = m.evaluation
  if (!e) return <p>No evaluation results yet. Run <code>uv run --project backend python scripts/evaluate.py</code>.</p>
  const all = e.scanner.ALL
  const llmRun = typeof e.llm !== 'string'
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card k="Poisoning recall (scanner, flagged)" v={f(all.recall_flagged_pct)} />
        <Card k="Benign acceptance" v={f(all.benign_acceptance_pct)} />
        <Card k="Drift detection*" v={f(e.drift_recall_pct)} />
        <Card k="Median scanner latency" v={`${e.scanner_latency_ms.p50} ms`} />
      </div>
      <p className="text-xs text-zinc-400">* Within the exact fields and capture path evaluated. False drift from key order/whitespace: {e.false_drift}/{e.false_drift_cases}. Sets frozen: {String(e.sets_frozen_intact)} ({e.frozen_sha256.slice(0, 12)}…).</p>
      <table className="w-full text-left text-sm">
        <caption className="mb-2 text-left font-semibold">Scanner vs LLM vs combined (recall = blocked / flagged)</caption>
        <thead className="text-zinc-400"><tr><th>Set</th><th>Scanner</th><th>LLM only</th><th>Combined</th><th>Benign accepted (scanner)</th></tr></thead>
        <tbody>
          {['authored.json', 'public_heldout.json', 'evasive.json', 'ALL'].map((s) => (
            <tr key={s} className="border-t border-zinc-800">
              <td className="py-1">{s.replace('.json', '')}</td>
              <td>{f(e.scanner[s].recall_blocked_pct)} / {f(e.scanner[s].recall_flagged_pct)}</td>
              <td>{llmRun ? `${f(e.llm[s].recall_blocked_pct)} / ${f(e.llm[s].recall_flagged_pct)}` : 'not run'}</td>
              <td>{llmRun ? `${f(e.combined[s].recall_blocked_pct)} / ${f(e.combined[s].recall_flagged_pct)}` : 'not run'}</td>
              <td>{f(e.scanner[s].benign_acceptance_pct)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!llmRun && <p className="text-sm text-amber-300">LLM columns were not run: no ANALYZER_API_KEY. Nothing is estimated.</p>}
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded border border-zinc-700 p-3"><h3 className="font-semibold">Missed by scanner (real false negatives)</h3><p className="font-mono text-sm">{e.scanner.missed.join(', ') || 'none'}</p></div>
        <div className="rounded border border-zinc-700 p-3"><h3 className="font-semibold">False positives on benign</h3><p className="font-mono text-sm">{e.scanner.false_positives.join(', ') || 'none'}</p></div>
      </div>
      <p className="text-xs text-zinc-400">{e.note}</p>
      <p className="text-xs text-zinc-400">Live counters: {m.blocked_count} calls blocked · {m.manifest_drift_count} drift events · {m.approval_count} approvals</p>
    </div>
  )
}

const Card = ({ k, v }: { k: string; v: string }) => (
  <div className="rounded border border-zinc-700 bg-zinc-900 p-4"><p className="text-xs text-zinc-400">{k}</p><p className="text-3xl font-bold">{v}</p></div>
)
