"""ToolTrustView: the single object the UI renders. UI never makes security decisions."""
from typing import Literal
from pydantic import BaseModel

TrustState = Literal["DISCOVERED", "REVIEW", "TRUSTED", "STALE", "BLOCKED"]
Severity = Literal["low", "medium", "high", "critical"]


class Finding(BaseModel):
    source: Literal["scanner", "llm"]
    category: str
    severity: Severity
    evidence: str
    confidence: Literal["low", "medium", "high"] | None = None


class Approval(BaseModel):
    status: Literal["approved", "denied", "stale", "none"]
    fingerprint: str | None = None
    approved_at: str | None = None


class Views(BaseModel):
    human_rendering: str          # simulated typical client (strips invisibles, truncates)
    model_visible_escaped: str    # exact text with [U+XXXX] markers
    hidden_char_count: int
    decoded_hidden_text: str | None = None


class Analysis(BaseModel):
    mode: Literal["live", "replay"]
    status: Literal["complete", "unavailable", "pending"]
    risk: Literal["none", "low", "medium", "high", "critical"]
    findings: list[Finding]


class Drift(BaseModel):
    detected: bool
    changed_fields: list[str] = []


class Decision(BaseModel):
    action: Literal["allow", "review", "block"]  # allow = eligible/currently valid
    reason_codes: list[str] = []


class ToolTrustView(BaseModel):
    tool: dict[str, str]    # id, name, title
    server: dict[str, str]  # id
    trust_state: TrustState
    approval: Approval
    current_fingerprint: str
    views: Views
    analysis: Analysis
    drift: Drift
    decision: Decision
    eligibility: Decision | None = None  # may the *current* manifest be approved? (shown for STALE/REVIEW)
