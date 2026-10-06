import { Ban, Check, TriangleAlert, RefreshCw, Search } from 'lucide-react'
import type { TrustState } from '../types'

const S: Record<TrustState, { label: string; cls: string; Icon: typeof Check }> = {
  TRUSTED: { label: 'TRUSTED', cls: 'bg-emerald-900/60 text-emerald-200 border-emerald-500', Icon: Check },
  REVIEW: { label: 'REVIEW REQUIRED', cls: 'bg-amber-900/60 text-amber-200 border-amber-500', Icon: TriangleAlert },
  BLOCKED: { label: 'BLOCKED', cls: 'bg-red-900/60 text-red-200 border-red-500', Icon: Ban },
  STALE: { label: 'STALE', cls: 'bg-violet-900/60 text-violet-200 border-violet-400', Icon: RefreshCw },
  DISCOVERED: { label: 'DISCOVERED', cls: 'bg-sky-900/60 text-sky-200 border-sky-500', Icon: Search },
}

export function StatusBadge({ state }: { state: TrustState }) {
  const { label, cls, Icon } = S[state]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-semibold ${cls}`}>
      <Icon size={14} aria-hidden /> {label}
    </span>
  )
}
