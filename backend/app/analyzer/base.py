"""Stage-2 semantic analyzer contract (PRD §13). The analyzer is advisory: it can add findings, never remove scanner ones."""
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

from ..api.schemas import Finding

PROMPT_VERSION = "p1"  # bump when the prompt/schema changes: it is part of the replay-cache key (D-22)

Category = Literal["hidden_instruction", "invisible_content", "purpose_mismatch", "sensitive_resource_request",
                   "external_exfiltration", "cross_tool_instruction", "concealment_instruction", "name_collision",
                   "schema_risk", "other"]


class LlmFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Category
    severity: Literal["low", "medium", "high", "critical"]
    evidence: str
    confidence: Literal["low", "medium", "high"]


class LlmOutput(BaseModel):
    """Strict analyzer output. Anything that does not validate is treated as ANALYSIS_UNAVAILABLE, never as safe."""
    model_config = ConfigDict(extra="forbid")
    declared_purpose: str
    risk_level: Literal["none", "low", "medium", "high", "critical"]
    findings: list[LlmFinding]
    recommended_action: Literal["allow", "review", "block"]


class AnalysisResult(BaseModel):
    mode: Literal["live", "replay"]
    status: Literal["complete", "unavailable"]
    findings: list[Finding] = []
    latency_ms: float = 0
    note: str | None = None


def to_result(out: LlmOutput, mode: str, latency_ms: float) -> AnalysisResult:
    fs = [Finding(source="llm", category=f.category, severity=f.severity, evidence=f.evidence[:200], confidence=f.confidence)
          for f in out.findings]
    return AnalysisResult(mode=mode, status="complete", findings=fs, latency_ms=latency_ms)


class SemanticAnalyzer(Protocol):
    mode: str

    async def analyze(self, manifest: dict, fingerprint: str, scanner_findings: list[Finding]) -> AnalysisResult: ...
