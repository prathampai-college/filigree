import { useState } from 'react'
import { api } from '../api'

type Line = { kind: 'req' | 'res' | 'human' | 'attacker' | 'blocked'; text: string }
const COLOR: Record<Line['kind'], string> = {
  req: 'text-zinc-400', res: 'text-zinc-100', human: 'text-emerald-300', attacker: 'text-amber-300', blocked: 'font-bold text-red-300',
}
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms))

// Plays a complete MCP session against /mcp/<server_id>: the same JSON-RPC a real client (Claude Desktop, Cursor) sends.
export function GatewaySession({ onDone }: { onDone: () => void }) {
  const [lines, setLines] = useState<Line[]>([])
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string>()

  const play = async () => {
    setBusy(true); setErr(undefined); setLines([])
    const say = async (kind: Line['kind'], text: string) => { setLines((l) => [...l, { kind, text }]); await pause(500) }
    let id = 0
    try {
      await api.reset()
      const { server_id: sid } = await api.scenario('rugpull')
      const rpc = async (method: string, params?: object) => {
        await say('req', `→ ${method}${params ? ' ' + JSON.stringify(params) : ''}`)
        const r = await fetch(`/mcp/${sid}`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) })
        return (await r.json()).result
      }
      const list = async () => {
        const names: string[] = ((await rpc('tools/list')).tools ?? []).map((t: { name: string }) => t.name)
        await say('res', `← ${names.length ? 'tools: ' + names.join(', ') : 'no tools offered'}`)
      }
      const call = async () => {
        const r = await rpc('tools/call', { name: 'fetch_report', arguments: { id: '7' } })
        await say(r.isError ? 'blocked' : 'res', `← ${r.isError ? 'isError' : 'ok'}: ${r.content[0].text}`)
      }
      await rpc('initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'any-mcp-client' } })
      await say('res', '← filigree-gateway ready')
      await list()
      await say('human', 'Human reviews fetch_report in Filigree and approves it')
      await api.approve(`${sid}:fetch_report`)
      await list()
      await call()
      await say('attacker', 'Server silently changes the tool definition (rug pull)')
      await api.mutate('modified')
      await call()
      await list()
      onDone()
    } catch (e) { setErr(e instanceof Error ? e.message : String(e)) } finally { setBusy(false) }
  }

  return (
    <section className="space-y-3">
      <h2 className="text-xl font-semibold">Real MCP client through the gateway</h2>
      <p className="text-sm text-zinc-400">
        Plays a full session over <code>/mcp/srv-rugpull</code> using raw JSON-RPC, the same messages Claude Desktop or Cursor send. Resets the demo state first.
      </p>
      <button disabled={busy} onClick={play} className="rounded bg-sky-800 px-3 py-1 text-sm font-semibold disabled:opacity-40">{busy ? 'Running…' : 'Run gateway session'}</button>
      {err && <div role="alert" className="rounded border border-red-500 bg-red-950 p-3 text-sm">{err}</div>}
      {lines.length > 0 && (
        <pre role="log" className="overflow-x-auto rounded border border-zinc-700 bg-zinc-900 p-4 font-mono text-sm">
          {lines.map((l, i) => <div key={i} className={COLOR[l.kind]}>{l.text}</div>)}
        </pre>
      )}
    </section>
  )
}
