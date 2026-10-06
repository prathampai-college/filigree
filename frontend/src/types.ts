// Mirror of backend/app/api/schemas.py
export type TrustState = 'DISCOVERED' | 'REVIEW' | 'TRUSTED' | 'STALE' | 'BLOCKED'
export type Severity = 'low' | 'medium' | 'high' | 'critical'

export type Finding = {
  source: 'scanner' | 'llm'
  category: string
  severity: Severity
  evidence: string
  confidence?: 'low' | 'medium' | 'high'
}

export type ToolTrustView = {
  tool: { id: string; name: string; title: string }
  server: { id: string }
  trust_state: TrustState
  approval: { status: 'approved' | 'denied' | 'stale' | 'none'; fingerprint?: string; approved_at?: string }
  current_fingerprint: string
  views: { human_rendering: string; model_visible_escaped: string; hidden_char_count: number; decoded_hidden_text?: string }
  analysis: { mode: 'live' | 'replay'; status: 'complete' | 'unavailable' | 'pending'; risk: 'none' | Severity; findings: Finding[] }
  drift: { detected: boolean; changed_fields: string[] }
  decision: { action: 'allow' | 'review' | 'block'; reason_codes: string[] }
  eligibility?: { action: 'allow' | 'review' | 'block'; reason_codes: string[] }
}
