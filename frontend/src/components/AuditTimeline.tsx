import { useEffect, useState } from 'react'
import { api, short, type AuditEvent } from '../api'

type Data = { events: AuditEvent[]; chain_verified: boolean; broken_at: number | null }

export function AuditTimeline({ tick, tool, limit = 10, controls = false }: { tick: number; tool?: string; limit?: number; controls?: boolean }) {
  const [data, setData] = useState<Data>()
  const [all, setAll] = useState(false)
  const [demo, setDemo] = useState(false)
  const [n, setN] = useState(0) // local refresh after verify / tamper
  useEffect(() => { api.audit().then(setData).catch(() => {}) }, [tick, n])
  useEffect(() => { if (controls) api.mode().then((m) => setDemo(m.demo)).catch(() => {}) }, [controls])
  if (!data) return <p className="text-sm text-zinc-400">Loading audit…</p>
  const evs = data.events.filter((e) => !tool || `${e.server_id}:${e.tool_name}` === tool).slice(0, all ? 200 : limit)
  const run = (p: Promise<unknown>) => p.then(() => setN((x) => x + 1)).catch(() => {})
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <p role="status" className={`text-xs font-semibold ${data.chain_verified ? 'text-emerald-300' : 'text-red-300'}`}>
          {data.chain_verified ? '✓ audit chain verified' : `✕ AUDIT CHAIN BROKEN at event #${data.broken_at}`}
        </p>
        {controls && (
          <>
            <button className="rounded border border-zinc-600 px-2 py-0.5 text-xs hover:border-zinc-300" onClick={() => setN((x) => x + 1)}>Verify chain</button>
            <a className="rounded border border-zinc-600 px-2 py-0.5 text-xs hover:border-zinc-300" href="/api/audit/export" download>Export JSON</a>
            <a className="rounded border border-zinc-600 px-2 py-0.5 text-xs hover:border-zinc-300" href="/api/lock" download title="Approved tool definitions, pinned; check them in CI with scripts/filigree_verify.py">Download filigree.lock</a>
            {demo && (data.chain_verified
              ? <button className="rounded border border-red-500 px-2 py-0.5 text-xs text-red-300 hover:bg-red-950" onClick={() => run(api.tamper())}>Tamper with an event (demo)</button>
              : <button className="rounded border border-emerald-500 px-2 py-0.5 text-xs text-emerald-300 hover:bg-emerald-950" onClick={() => run(api.untamper())}>Restore (demo)</button>)}
          </>
        )}
      </div>
      <ol className="space-y-1 font-mono text-xs">
        {evs.map((e) => (
          <li key={e.id} className={`grid grid-cols-[64px_220px_1fr] gap-2 ${e.id === data.broken_at ? 'rounded bg-red-950 outline outline-1 outline-red-500' : ''}`}>
            <span className="text-zinc-500">{new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false })}</span>
            <span className="font-semibold">{e.event_type.replace(/_/g, ' ')}</span>
            <span className="text-zinc-300 break-words">
              {e.tool_name} {e.current_fingerprint && short(e.current_fingerprint)}
              {e.changed_fields.length > 0 && ` · changed: ${e.changed_fields.join(', ')}`}
              {e.reason && ` · ${e.reason}`}
              {e.id === data.broken_at && ' · ← hash does not match (edited after the fact)'}
            </span>
          </li>
        ))}
        {evs.length === 0 && <li className="text-zinc-500">No events yet.</li>}
      </ol>
      {data.events.length > limit && (
        <button className="mt-2 text-xs underline" onClick={() => setAll(!all)}>{all ? 'show fewer' : 'show all'}</button>
      )}
    </div>
  )
}
