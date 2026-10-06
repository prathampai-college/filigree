import { useState } from 'react'
import type { ToolTrustView } from '../types'
import { needlesFrom, short } from '../api'
import { MarkedText } from './HiddenCharMarker'
import { FindingCard } from './FindingCard'
import { StatusBadge } from './StatusBadge'

const STATE_COPY: Record<string, string> = {
  TRUSTED: 'Approved. Current manifest matches the approved manifest.',
  REVIEW: 'Human decision required.',
  BLOCKED: 'Execution denied by policy.',
  STALE: 'Previously approved, but the security-relevant representation changed.',
  DISCOVERED: 'Discovered; analysis pending.',
}

type Props = { v: ToolTrustView; onApprove?: (confirm: boolean) => void; onBlock?: () => void }

// Button rules (DESIGN §5 / D-12): no Approve for high/critical or integrity failure; medium needs a confirmation step.
export function ApprovalCard({ v, onApprove, onBlock }: Props) {
  const [confirming, setConfirming] = useState(false)
  const [mark, setMark] = useState(true)
  const reviewing = v.trust_state === 'REVIEW' || v.trust_state === 'STALE'
  const elig = reviewing ? (v.eligibility ?? v.decision) : undefined
  const stale = v.trust_state === 'STALE'
  const reasons = v.decision.reason_codes.join(', ')
  const needles = needlesFrom(v.analysis.findings.map((f) => f.evidence)).filter((n) => v.views.model_visible_escaped.toLowerCase().includes(n.toLowerCase()))

  return (
    <section className="space-y-4">
      <header className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold">{v.tool.title}</h2>
          <p className="text-sm text-zinc-400">Server: {v.server.id} (host-assigned)</p>
        </div>
        <div className="text-right">
          <StatusBadge state={v.trust_state} />
          <p className="mt-1 max-w-64 text-xs text-zinc-400">{STATE_COPY[v.trust_state]}</p>
        </div>
      </header>

      {v.analysis.status !== 'complete' && (
        <div role="status" className="rounded border border-amber-500 bg-amber-950/60 p-3 text-sm">
          ANALYSIS UNAVAILABLE — current policy: REVIEW REQUIRED. Scanner results shown.
        </div>
      )}

      {v.drift.detected && (
        <div role="alert" className="rounded border-2 border-red-500 bg-red-950 p-4">
          <p className="text-xl font-bold">⛔ APPROVAL INVALID</p>
          <p>This tool changed after you approved it.</p>
          <div className="mt-2 grid grid-cols-2 gap-4 font-mono text-xs">
            <div><span className="text-zinc-400">Approved fingerprint</span><br />{short(v.approval.fingerprint)}</div>
            <div><span className="text-zinc-400">Current fingerprint</span><br />{short(v.current_fingerprint)}</div>
          </div>
          <p className="mt-2 text-sm">{v.drift.changed_fields.length} security-relevant field(s) changed: {v.drift.changed_fields.join(', ')}</p>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded border border-zinc-700 bg-zinc-900 p-4">
          <h3 className="text-xs font-semibold text-zinc-400">WHAT YOU SEE · typical client rendering (simulated)</h3>
          <p className="mt-2 text-sm break-words">{v.views.human_rendering}</p>
        </div>
        <div className="rounded border border-zinc-700 bg-zinc-900 p-4">
          <h3 className="text-xs font-semibold text-zinc-400">WHAT THE MODEL RECEIVES · exact registered text</h3>
          <div className="mt-2"><MarkedText text={v.views.model_visible_escaped} needles={mark ? needles : []} /></div>
          {needles.length > 0 && (
            <label className="mt-2 flex items-center gap-2 text-xs text-zinc-400">
              <input type="checkbox" checked={mark} onChange={(e) => setMark(e.target.checked)} />
              Highlight what the scanner flagged ({needles.length})
            </label>
          )}
          {v.views.hidden_char_count > 0 && (
            <p className="mt-2 text-sm text-red-300">
              ⚠ {v.views.hidden_char_count} hidden characters
              {v.views.decoded_hidden_text && <> — decoded: <span className="font-mono">"{v.views.decoded_hidden_text}"</span></>}
            </p>
          )}
        </div>
      </div>

      {v.views.human_rendering !== v.views.model_visible_escaped && (
        <p role="alert" className="text-center text-sm font-bold tracking-wide text-red-300">— MISMATCH DETECTED: the model receives text you do not see —</p>
      )}

      {v.analysis.findings.length > 0 && (
        <div className="space-y-2">
          <h3 className="font-semibold">{v.decision.action === 'block' ? 'Why this is blocked' : 'Findings'}</h3>
          {v.analysis.findings.map((f, i) => <FindingCard key={i} f={f} />)}
        </div>
      )}
      {reasons && <p className="text-sm text-zinc-400">Reason codes: {reasons}</p>}
      {v.trust_state === 'TRUSTED' && <p className="text-xs text-zinc-400">APPROVED · MANIFEST CURRENT · {short(v.approval.fingerprint)} · {v.analysis.mode.toUpperCase()} analysis</p>}

      {confirming && (
        <div className="rounded border border-amber-500 bg-amber-950/60 p-3 text-sm">
          <p className="font-semibold">Confirm approval despite: {elig?.reason_codes.join(', ')}</p>
          <p className="text-zinc-300">You are approving this exact representation ({short(v.current_fingerprint)}) with the findings above.</p>
          <button className="mt-2 rounded bg-amber-600 px-3 py-1 font-semibold text-black" onClick={() => { setConfirming(false); onApprove?.(true) }}>
            Confirm and approve
          </button>
        </div>
      )}

      <footer className="flex justify-end gap-2">
        <button className="rounded bg-red-700 px-4 py-2 font-semibold hover:bg-red-600" onClick={onBlock}>BLOCK TOOL</button>
        {elig?.action === 'allow' && (
          <button className="rounded bg-emerald-700 px-4 py-2 font-semibold hover:bg-emerald-600" onClick={() => onApprove?.(false)}>
            {stale ? 'REVIEW NEW VERSION → APPROVE' : 'APPROVE'}
          </button>
        )}
        {elig?.action === 'review' && !confirming && (
          <button className="rounded border border-amber-500 px-4 py-2 hover:bg-amber-950" onClick={() => setConfirming(true)}>Approve…</button>
        )}
      </footer>
    </section>
  )
}
