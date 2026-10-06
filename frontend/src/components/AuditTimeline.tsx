import { useEffect, useState } from 'react'
import { api, short, type AuditEvent } from '../api'

export function AuditTimeline({ tick, tool, limit = 10 }: { tick: number; tool?: string; limit?: number }) {
  const [data, setData] = useState<{ events: AuditEvent[]; chain_verified: boolean }>()
  const [all, setAll] = useState(false)
  useEffect(() => { api.audit().then(setData).catch(() => {}) }, [tick])
  if (!data) return <p className="text-sm text-zinc-400">Loading audit…</p>
  const evs = data.events.filter((e) => !tool || `${e.server_id}:${e.tool_name}` === tool).slice(0, all ? 200 : limit)
  return (
    <div>
      <p className={`mb-2 text-xs ${data.chain_verified ? 'text-emerald-300' : 'text-red-300'}`}>
        {data.chain_verified ? '✓ audit chain verified' : '✕ AUDIT CHAIN BROKEN'}
      </p>
      <ol className="space-y-1 font-mono text-xs">
        {evs.map((e) => (
          <li key={e.id} className="grid grid-cols-[64px_220px_1fr] gap-2">
            <span className="text-zinc-500">{new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false })}</span>
            <span className="font-semibold">{e.event_type.replace(/_/g, ' ')}</span>
            <span className="text-zinc-300 break-words">
              {e.tool_name} {e.current_fingerprint && short(e.current_fingerprint)}
              {e.changed_fields.length > 0 && ` · changed: ${e.changed_fields.join(', ')}`}
              {e.reason && ` · ${e.reason}`}
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
