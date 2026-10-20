from app.firewall.input_firewall import detect_prompt_injection
from app.firewall.policy import make_decision
from app.firewall.tool_firewall import execute_tool, tool_registry
from app.firewall.audit import log_audit_event
from app.models.schemas import AuditEventType, Decision


def inspect_input(user_input: str, correlation_id: str = None, user_id: str = None):
    analysis = detect_prompt_injection(user_input)
    decision = make_decision(analysis["risk"])

    event_type = AuditEventType.INPUT_INSPECTION
    if decision == Decision.BLOCK.value:
        event_type = AuditEventType.INPUT_BLOCKED
    elif decision == Decision.CONFIRM.value:
        event_type = AuditEventType.INPUT_CONFIRM

    log_audit_event(
        event_type=event_type,
        policy_decision=Decision(decision),
        outcome="inspected",
        risk_score=analysis["risk"],
        correlation_id=correlation_id,
        user_id=user_id,
        details={
            "detected": analysis["detected"],
            "reason": analysis["reason"],
            "matches": analysis["matches"],
        },
    )

    return {
        "risk": analysis["risk"],
        "decision": decision,
        "detected": analysis["detected"],
        "reason": analysis["reason"],
        "matches": analysis["matches"],
    }


__all__ = [
    "inspect_input",
    "execute_tool",
    "tool_registry",
]