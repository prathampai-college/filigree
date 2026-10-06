import type { Change } from '../api'
import { EscapedText } from './HiddenCharMarker'

// +/- gutters and labels: the diff never relies on color alone.
export function DiffViewer({ changes }: { changes: Change[] }) {
  if (!changes.length) return <p className="text-sm text-zinc-400">No security-relevant changes against the approved manifest.</p>
  return (
    <div className="space-y-4">
      {changes.map((c) => (
        <div key={c.field} className="rounded border border-zinc-700 bg-zinc-900 p-3">
          <h4 className="text-xs font-semibold uppercase text-zinc-400">{c.field}</h4>
          <pre className="mt-2 overflow-x-auto font-mono text-sm whitespace-pre-wrap">
            {c.lines?.length
              ? c.lines.filter((l) => !/^(---|\+\+\+|@@)/.test(l)).map((l, i) => (
                  <div key={i} className={l[0] === '+' ? 'bg-emerald-900/40' : l[0] === '-' ? 'bg-red-900/40' : ''}>
                    <span aria-label={l[0] === '+' ? 'added' : l[0] === '-' ? 'removed' : 'unchanged'}>{l[0] === ' ' || !'+-'.includes(l[0]) ? ' ' : l[0]}</span>{' '}
                    <EscapedInline text={l.slice(1)} />
                  </div>
                ))
              : (
                <>
                  <div className="bg-red-900/40">− {JSON.stringify(c.before) ?? '(absent)'}</div>
                  <div className="bg-emerald-900/40">+ {JSON.stringify(c.after) ?? '(removed)'}</div>
                </>
              )}
          </pre>
          {c.hidden_chars && (
            <p className="mt-2 text-sm text-red-300">
              ⚠ hidden characters: {c.hidden_chars.before} → {c.hidden_chars.after} (+{c.hidden_chars.after - c.hidden_chars.before})
            </p>
          )}
        </div>
      ))}
    </div>
  )
}

const EscapedInline = ({ text }: { text: string }) => <EscapedText text={text} inline />
