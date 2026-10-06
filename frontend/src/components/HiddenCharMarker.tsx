// Renders escaped text: [U+XXXX] markers become highlighted chips. Long runs collapse to a count
// (the Manifest tab keeps every marker; collapse=false shows them all).
const RUN = /((?:\[U\+[0-9A-F]{4,6}\]){6,})/g
const ONE = /\[U\+[0-9A-F]{4,6}\]/g

export function EscapedText({ text, inline = false, collapse = true }: { text: string; inline?: boolean; collapse?: boolean }) {
  const chip = (s: string, k: string | number) => <mark key={k} className="rounded bg-red-500/30 px-0.5 text-red-200">{s}</mark>
  const kids = text.split(collapse ? RUN : /(\[U\+[0-9A-F]{4,6}\])/g).map((p, i) => {
    if (collapse && /^(\[U\+[0-9A-F]{4,6}\]){6,}$/.test(p)) {
      const all = p.match(ONE)!
      return chip(`${all.slice(0, 3).join('')} …+${all.length - 3} hidden`, i)
    }
    return /^\[U\+/.test(p) ? chip(p, i) : <span key={i}>{p}</span>
  })
  return inline ? <span>{kids}</span> : <p className="font-mono text-sm break-words whitespace-pre-wrap">{kids}</p>
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

// Like EscapedText, but also underlines the phrases the scanner matched.
export function MarkedText({ text, needles }: { text: string; needles: string[] }) {
  if (!needles.length) return <EscapedText text={text} />
  const parts = text.split(new RegExp(`(${needles.map(esc).join('|')})`, 'gi'))
  return (
    <p className="font-mono text-sm break-words whitespace-pre-wrap">
      {parts.map((p, i) => i % 2
        ? <mark key={i} className="rounded bg-amber-400/25 px-0.5 underline decoration-amber-400 decoration-2">{p}</mark>
        : <EscapedText key={i} text={p} inline />)}
    </p>
  )
}
