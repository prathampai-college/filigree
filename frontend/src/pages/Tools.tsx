import { useEffect, useState } from 'react'
import { api, short, type Change } from '../api'
import type { ToolTrustView } from '../types'
import { ApprovalCard } from '../components/ApprovalCard'
import { AuditTimeline } from '../components/AuditTimeline'
import { DiffViewer } from '../components/DiffViewer'
import { EscapedText } from '../components/HiddenCharMarker'
import { StatusBadge } from '../components/StatusBadge'

const TABS = ['Approval', 'Diff', 'Audit', 'Manifest'] as const
type Tab = (typeof TABS)[number]

export function Tools({ tick, bump }: { tick: number; bump: () => void }) {
  const [views, setViews] = useState<ToolTrustView[]>([])
  const [sel, setSel] = useState<string>()
  const [tab, setTab] = useState<Tab>('Approval')
  const [err, setErr] = useState<string>()

  useEffect(() => {
    api.tools().then((v) => { setViews(v); setErr(undefined); setSel((s) => s ?? v[0]?.tool.id) })
      .catch(() => setErr('SECURITY CONTROL UNAVAILABLE — the execution decision cannot be verified.'))
  }, [tick])

  const v = views.find((x) => x.tool.id === sel)
  const count = (s: string) => views.filter((x) => x.trust_state === s).length
  const act = (p: Promise<unknown>) => p.then(() => { setErr(undefined); bump() }).catch((e) => setErr(String(e.message)))

  return (
    <div className="space-y-6">
      {err && <div role="alert" className="rounded border border-red-500 bg-red-950 p-3">{err}</div>}
      <div className="flex gap-6 text-lg font-semibold">
        <span className="text-emerald-300">{count('TRUSTED')} Trusted</span>
        <span className="text-amber-300">{count('REVIEW')} Review</span>
        <span className="text-violet-300">{count('STALE')} Stale</span>
        <span className="text-red-300">{count('BLOCKED')} Blocked</span>
      </div>
      <div className="grid gap-6 lg:grid-cols-[340px_1fr]">
        <ul className="space-y-2">
          {views.length === 0 && <li className="text-sm text-zinc-400">No tools yet. Open the Demo page and connect a scenario.</li>}
          {views.map((x) => (
            <li key={x.tool.id}>
              <button onClick={() => setSel(x.tool.id)} aria-current={x.tool.id === sel}
                className="w-full rounded border border-zinc-800 bg-zinc-900 p-3 text-left hover:border-zinc-600 aria-[current=true]:border-zinc-300">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{x.tool.name}</span><StatusBadge state={x.trust_state} />
                </div>
                <p className="mt-1 text-xs text-zinc-400">{x.server.id} · {reasonText(x)}</p>
              </button>
            </li>
          ))}
        </ul>
        {v && (
          <div>
            <div role="tablist" className="mb-4 flex gap-1 border-b border-zinc-800">
              {TABS.map((t) => (
                <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
                  className="px-3 py-2 text-sm aria-selected:border-b-2 aria-selected:border-zinc-200 aria-selected:font-semibold text-zinc-400 aria-selected:text-zinc-100">{t}</button>
              ))}
            </div>
            <p className="mb-3 text-xs text-zinc-400">MCP gateway for this server (only approved tools, every call gated):{' '}
              <code className="font-mono text-zinc-200">{`http://127.0.0.1:8000/mcp/${v.server.id}`}</code></p>
            {tab === 'Approval' && (
              <ApprovalCard v={v} onApprove={(c) => act(api.approve(v.tool.id, c))} onBlock={() => act(api.deny(v.tool.id))} />
            )}
            {tab === 'Diff' && <DiffTab id={v.tool.id} tick={tick} />}
            {tab === 'Audit' && <AuditTimeline tick={tick} tool={v.tool.id} limit={50} />}
            {tab === 'Manifest' && <ManifestTab id={v.tool.id} tick={tick} />}
          </div>
        )}
      </div>
    </div>
  )
}

function reasonText(v: ToolTrustView) {
  if (v.drift.detected) return `Tool definition changed after approval`
  if (v.trust_state === 'TRUSTED') return 'Approved manifest unchanged'
  return v.decision.reason_codes.join(', ') || 'Eligible for approval'
}

function DiffTab({ id, tick }: { id: string; tick: number }) {
  const [c, setC] = useState<Change[]>()
  useEffect(() => { api.diff(id).then((r) => setC(r.changes)) }, [id, tick])
  return c ? <DiffViewer changes={c} /> : <p>Loading…</p>
}

function ManifestTab({ id, tick }: { id: string; tick: number }) {
  const [m, setM] = useState<any>()
  useEffect(() => { api.manifest(id).then(setM) }, [id, tick])
  if (!m) return <p>Loading…</p>
  return (
    <div className="space-y-3 text-sm">
      <dl className="grid grid-cols-[160px_1fr] gap-y-1">
        <dt className="text-zinc-400">Manifest version</dt><dd>{m.manifest.manifest_version}</dd>
        <dt className="text-zinc-400">Server ID</dt><dd>{m.manifest.server.id}</dd>
        <dt className="text-zinc-400">Fingerprint</dt>
        <dd className="font-mono">{short(m.fingerprint)} <button className="ml-2 underline" onClick={() => navigator.clipboard?.writeText(m.fingerprint)}>copy full</button></dd>
        <dt className="text-zinc-400">Decision</dt><dd>{m.approval.status.toUpperCase()}</dd>
        <dt className="text-zinc-400">Policy version</dt><dd>{m.policy_version}</dd>
        <dt className="text-zinc-400">Analysis mode</dt><dd>{m.analysis_mode}</dd>
      </dl>
      <h4 className="font-semibold">Raw manifest (hidden characters escaped)</h4>
      <div className="rounded border border-zinc-700 bg-zinc-900 p-3"><EscapedText text={m.escaped_json} collapse={false} /></div>
    </div>
  )
}
