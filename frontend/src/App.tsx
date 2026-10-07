import { useEffect, useState } from 'react'
import { api, getToken, setToken } from './api'
import { Demo } from './pages/Demo'
import { Evaluation } from './pages/Evaluation'
import { Tools } from './pages/Tools'
import { AuditTimeline } from './components/AuditTimeline'

const PAGES = ['Tools', 'Demo', 'Audit', 'Evaluation'] as const
type Page = (typeof PAGES)[number]
const fromHash = (): Page => (PAGES.find((p) => `#${p.toLowerCase()}` === location.hash) ?? 'Tools')

export default function App() {
  const [page, setPage] = useState<Page>(fromHash)
  const [tick, setTick] = useState(0)
  const [mode, setMode] = useState<'live' | 'replay' | null>(null)
  const [recorded, setRecorded] = useState<string | null>(null)
  const bump = () => setTick((t) => t + 1)
  useEffect(() => { const h = () => setPage(fromHash()); addEventListener('hashchange', h); return () => removeEventListener('hashchange', h) }, [])
  useEffect(() => { api.mode().then((m) => { setMode(m.analyzer); setRecorded(m.recorded) }).catch(() => setMode(null)) }, [tick])

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <nav className="flex items-center justify-between border-b border-zinc-800 px-6 py-3">
        <div className="flex items-center gap-6">
          <span className="text-lg font-bold tracking-wide">Filigree</span>
          {PAGES.map((p) => (
            <a key={p} href={`#${p.toLowerCase()}`} aria-current={page === p} className="text-sm text-zinc-400 aria-[current=true]:font-semibold aria-[current=true]:text-zinc-100">{p}</a>
          ))}
        </div>
        <div className="flex items-center gap-3">
        <input type="password" aria-label="Approver token" placeholder="approver token (if auth is on)" defaultValue={getToken()}
          onChange={(e) => setToken(e.target.value)} className="w-52 rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-xs" />
        <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${mode === 'live' ? 'border-sky-400 text-sky-300' : 'border-amber-500 text-amber-300'}`}>
          {mode === 'live' ? 'LIVE ANALYSIS' : mode === 'replay' ? (recorded ? `REPLAY MODE · recorded from ${recorded}` : 'REPLAY MODE · authored analysis') : 'BACKEND UNAVAILABLE'}
        </span>
        </div>
      </nav>
      <main className="mx-auto max-w-6xl p-6">
        {page === 'Tools' && <Tools tick={tick} bump={bump} />}
        {page === 'Demo' && <Demo tick={tick} bump={bump} />}
        {page === 'Audit' && <AuditTimeline tick={tick} limit={25} controls />}
        {page === 'Evaluation' && <Evaluation tick={tick} />}
      </main>
    </div>
  )
}
