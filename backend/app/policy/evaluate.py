"""Policy engine (D-06, D-12, D-25). Pure and deterministic. Priority: integrity > authz > high > medium > clean."""
from ..api.schemas import Decision, Drift, Finding

_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def merge_findings(scanner: list[Finding], llm: list[Finding]) -> list[Finding]:
    """LLM findings are additive; scanner findings are always kept as-is."""
    return scanner + [f for f in llm if f.source == "llm"]


def risk_of(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=_RANK.get, default="none")


def _deny(findings: list[Finding]) -> list[str]:
    return ["CLOAKING_SUSPECTED"] if any(f.category == "cloaking" for f in findings) else ["POLICY_DENY"]


def eligibility(findings: list[Finding], analysis_ok: bool) -> Decision:
    """Approval time: may this manifest be presented for approval? allow = eligible, never auto-approve."""
    r = _RANK.get(risk_of(findings), 0)
    if r >= 3:
        return Decision(action="block", reason_codes=_deny(findings))
    codes = (["MEDIUM_FINDING"] if r == 2 else []) + ([] if analysis_ok else ["ANALYSIS_UNAVAILABLE"])
    return Decision(action="review" if codes else "allow", reason_codes=codes)


def gate_decision(current_fp: str | None, approved_fp: str | None, findings: list[Finding],
                  changed: list[str] = ()) -> tuple[Decision, Drift]:
    """Call time. Human already approved (incl. confirmed medium), so only integrity + high findings block."""
    if current_fp is None:
        return Decision(action="block", reason_codes=["CAPTURE_FAILURE"]), Drift(detected=False)
    if approved_fp is None:
        return Decision(action="block", reason_codes=["NO_APPROVAL"]), Drift(detected=False)
    if current_fp != approved_fp:
        return Decision(action="block", reason_codes=["MANIFEST_DRIFT"]), Drift(detected=True, changed_fields=list(changed))
    if _RANK.get(risk_of(findings), 0) >= 3:
        return Decision(action="block", reason_codes=_deny(findings)), Drift(detected=False)
    return Decision(action="allow"), Drift(detected=False)
