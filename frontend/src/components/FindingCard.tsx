import type { Finding } from '../types'

const SEV: Record<string, string> = {
  critical: 'text-red-300', high: 'text-red-300', medium: 'text-amber-300', low: 'text-sky-300',
}

export function FindingCard({ f }: { f: Finding }) {
  return (
    <div className="rounded border border-zinc-700 bg-zinc-900 p-3">
      <div className="flex flex-wrap gap-x-4 text-xs font-semibold uppercase">
        <span className={SEV[f.severity]}>{f.severity}</span>
        <span>{f.category.replace(/_/g, ' ')}</span>
        <span className="font-normal text-zinc-400 normal-case">source: {f.source}</span>
        {f.confidence && <span className="font-normal text-zinc-500 normal-case">confidence: {f.confidence}</span>}
      </div>
      <p className="mt-2 text-xs text-zinc-400">Evidence</p>
      <p className="font-mono text-sm break-words">{f.evidence}</p>
    </div>
  )
}
