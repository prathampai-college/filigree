import type { ToolTrustView } from './types'

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...init })
  if (!r.ok) throw new Error((await r.json().catch(() => ({ detail: r.statusText }))).detail ?? r.statusText)
  return r.json()
}
const post = <T,>(p: string, body?: unknown) => j<T>(p, { method: 'POST', body: body ? JSON.stringify(body) : undefined })
const enc = encodeURIComponent

export type Change = { field: string; before: unknown; after: unknown; lines?: string[]; hidden_chars?: { before: number; after: number } }
export type AuditEvent = {
  id: number; ts: number; event_type: string; server_id: string | null; tool_name: string | null
  previous_fingerprint: string | null; current_fingerprint: string | null; changed_fields: string[]; reason: string | null
}
export type AttackResult = { succeeded: boolean; log: string[]; followed?: string }
export type Playground = {
  baseline_fingerprint: string; current_fingerprint: string; approval_stale: boolean
  findings: ToolTrustView['analysis']['findings']; decision: ToolTrustView['decision']; risk: string
  views: ToolTrustView['views']; note: string
}

export const api = {
  mode: () => j<{ analyzer: 'live' | 'replay'; demo: boolean; recorded: string | null }>('/api/mode'),
  tools: () => j<ToolTrustView[]>('/api/tools'),
  diff: (id: string) => j<{ changes: Change[] }>(`/api/tools/${enc(id)}/diff`),
  manifest: (id: string) => j<{ fingerprint: string; manifest: unknown }>(`/api/tools/${enc(id)}/manifest`),
  approve: (id: string, confirm = false) => post<ToolTrustView>(`/api/tools/${enc(id)}/approve`, { confirm }),
  deny: (id: string) => post<ToolTrustView>(`/api/tools/${enc(id)}/deny`),
  audit: () => j<{ events: AuditEvent[]; chain_verified: boolean; broken_at: number | null }>('/api/audit'),
  tamper: () => post<{ tampered_id: number }>('/api/demo/tamper'),
  untamper: () => post('/api/demo/untamper'),
  metrics: () => j<Record<string, any>>('/api/metrics'),
  call: (server_id: string, tool: string, args: object = {}) =>
    post<{ allowed: boolean; reason_codes: string[]; changed_fields: string[]; result: string | null }>('/api/agent/call', { server_id, tool, args }),
  scenarios: () => j<{ scenarios: string[]; agent_label: string }>('/api/demo/scenarios'),
  reset: () => post('/api/demo/reset'),
  scenario: (name: string) => post<{ server_id: string }>('/api/demo/scenario', { name }),
  mutate: (mode = 'modified') => post('/api/demo/mutate', { mode }),
  attack: (server_id: string, tool: string, protected_: boolean, agent: 'scripted' | 'llm' = 'scripted') =>
    post<AttackResult>('/api/demo/attack', { server_id, tool, protected: protected_, agent }),
  playground: (description: string, baseline_description?: string) =>
    post<Playground>('/api/playground/analyze', { description, baseline_description }),
}

export const short = (h?: string | null) => (h ? `${h.slice(0, 15)}…${h.slice(-4)}` : '—')

// Scanner evidence reads "<field>: <label>: <matched text>"; the matched tail is what we look for in the model-visible text.
export const needlesFrom = (evidence: string[]) =>
  evidence.map((e) => (e.split(': ').pop() ?? '').replace(/^(references|destination) /, '').replace(/^"|"$/g, '')).filter((n) => n.length >= 4)
