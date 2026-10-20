from typing import Any, Dict, List, Optional, Tuple
from app.firewall.behavior_models import (
    BehavioralAssessment,
    BehavioralEvent,
    BehavioralEventType,
    BehavioralIndicator,
    DataSensitivity,
    UserIntent,
)
from app.firewall.intent import is_tool_justified_for_intent
from app.firewall.sensitivity import classify_resource_sensitivity
from app.models.schemas import Decision, SecurityContext

# Configurable Behavioral Risk Indicator Weights
INDICATOR_WEIGHTS: Dict[BehavioralIndicator, int] = {
    BehavioralIndicator.ACTION_OUTSIDE_REQUEST_SCOPE: 25,
    BehavioralIndicator.SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION: 35,
    BehavioralIndicator.SUSPICIOUS_ACTION_SEQUENCE: 40,
    BehavioralIndicator.SENSITIVE_DATA_MOVEMENT: 45,
    BehavioralIndicator.REPEATED_DENIED_ACTIONS: 20,  # Per denied action, capped
    BehavioralIndicator.UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION: 30,
    BehavioralIndicator.UNUSUAL_TOOL_CHAIN: 20,
    BehavioralIndicator.EXCESSIVE_TOOL_ACTIVITY: 15,
    BehavioralIndicator.UNEXPECTED_PRIVILEGE_ESCALATION: 30,
}

# Decision thresholds matching RAPHAEL 4-tier risk policy
THRESHOLD_ALLOW = 25
THRESHOLD_MONITOR = 50
THRESHOLD_CONFIRM = 75


def assess_behavior(
    tool_name: str,
    arguments: Dict[str, Any],
    user_intent: UserIntent,
    session_events: List[BehavioralEvent],
    security_context: Optional[SecurityContext] = None,
) -> BehavioralAssessment:
    """Evaluate behavioral risk of proposed tool execution across session context.

    Correlates user intent, historical events, data sensitivity, and tool chaining.
    Returns a deterministic, explainable BehavioralAssessment.
    """
    triggered_indicators: List[str] = []
    component_breakdown: Dict[str, int] = {}
    contributing_event_ids: List[str] = []
    reasons: List[str] = []

    sensitivity = classify_resource_sensitivity(tool_name, arguments)

    # 1. Indicator: ACTION_OUTSIDE_REQUEST_SCOPE
    if user_intent != UserIntent.UNKNOWN and not is_tool_justified_for_intent(tool_name, user_intent):
        weight = INDICATOR_WEIGHTS[BehavioralIndicator.ACTION_OUTSIDE_REQUEST_SCOPE]
        triggered_indicators.append(BehavioralIndicator.ACTION_OUTSIDE_REQUEST_SCOPE.value)
        component_breakdown[BehavioralIndicator.ACTION_OUTSIDE_REQUEST_SCOPE.value] = weight
        reasons.append(f"Tool '{tool_name}' falls outside user intent '{user_intent.value}'")

    # 2. Indicator: SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION
    if sensitivity in (DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED):
        if user_intent not in (UserIntent.DATABASE_LOOKUP, UserIntent.FILE_ACCESS):
            weight = INDICATOR_WEIGHTS[BehavioralIndicator.SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION]
            triggered_indicators.append(BehavioralIndicator.SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION.value)
            component_breakdown[BehavioralIndicator.SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION.value] = weight
            reasons.append(f"Accessing {sensitivity.value} resource without corresponding request intent")

    # 3. Analyze Historical Events in Session
    denied_events = [e for e in session_events if e.event_type == BehavioralEventType.TOOL_DENIED]
    executed_events = [e for e in session_events if e.event_type == BehavioralEventType.TOOL_EXECUTED]
    sensitive_read_events = [
        e for e in executed_events
        if e.tool_name in ("database_read", "file_read")
        and e.data_sensitivity in (DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED)
    ]
    untrusted_fetch_events = [
        e for e in executed_events
        if e.tool_name in ("web_search", "file_read")
    ]

    # 4. Indicator: REPEATED_DENIED_ACTIONS
    if denied_events:
        count = len(denied_events)
        per_weight = INDICATOR_WEIGHTS[BehavioralIndicator.REPEATED_DENIED_ACTIONS]
        denied_weight = min(40, count * per_weight)
        triggered_indicators.append(BehavioralIndicator.REPEATED_DENIED_ACTIONS.value)
        component_breakdown[BehavioralIndicator.REPEATED_DENIED_ACTIONS.value] = denied_weight
        contributing_event_ids.extend([e.event_id for e in denied_events])
        reasons.append(f"{count} previously denied action(s) detected in session")

    # 5. Indicator: SENSITIVE_DATA_MOVEMENT / SUSPICIOUS_ACTION_SEQUENCE
    # Accessing sensitive data followed by an outbound communication attempt (e.g. read confidential -> email)
    if tool_name == "send_email" and sensitive_read_events:
        weight = INDICATOR_WEIGHTS[BehavioralIndicator.SENSITIVE_DATA_MOVEMENT]
        triggered_indicators.append(BehavioralIndicator.SENSITIVE_DATA_MOVEMENT.value)
        component_breakdown[BehavioralIndicator.SENSITIVE_DATA_MOVEMENT.value] = weight
        contributing_event_ids.extend([e.event_id for e in sensitive_read_events])
        reasons.append(
            f"Attempt to send outbound email following read of sensitive data ({', '.join(e.tool_name for e in sensitive_read_events)})"
        )

    # 6. Indicator: UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION
    # If the immediately preceding tool call retrieved untrusted content, and current tool accesses sensitive resources
    if untrusted_fetch_events and executed_events:
        last_event = executed_events[-1]
        if last_event.tool_name in ("web_search", "file_read") and sensitivity in (DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED):
            weight = INDICATOR_WEIGHTS[BehavioralIndicator.UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION]
            triggered_indicators.append(BehavioralIndicator.UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION.value)
            component_breakdown[BehavioralIndicator.UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION.value] = weight
            contributing_event_ids.append(last_event.event_id)
            reasons.append(
                f"Sensitive tool '{tool_name}' invoked immediately after external/untrusted content retrieval from '{last_event.tool_name}'"
            )

    # 7. Indicator: UNUSUAL_TOOL_CHAIN
    if executed_events:
        last_tool = executed_events[-1].tool_name
        # Flag abnormal transitions such as calculator -> send_email, database_read, or file_read
        if last_tool == "calculator" and tool_name in ("send_email", "database_read", "file_read"):
            weight = INDICATOR_WEIGHTS[BehavioralIndicator.UNUSUAL_TOOL_CHAIN]
            triggered_indicators.append(BehavioralIndicator.UNUSUAL_TOOL_CHAIN.value)
            component_breakdown[BehavioralIndicator.UNUSUAL_TOOL_CHAIN.value] = weight
            contributing_event_ids.append(executed_events[-1].event_id)
            reasons.append(f"Anomalous tool transition from '{last_tool}' to '{tool_name}'")

    # 8. Indicator: EXCESSIVE_TOOL_ACTIVITY
    if len(executed_events) >= 4:
        weight = INDICATOR_WEIGHTS[BehavioralIndicator.EXCESSIVE_TOOL_ACTIVITY]
        triggered_indicators.append(BehavioralIndicator.EXCESSIVE_TOOL_ACTIVITY.value)
        component_breakdown[BehavioralIndicator.EXCESSIVE_TOOL_ACTIVITY.value] = weight
        reasons.append(f"High volume of tool invocations ({len(executed_events)} completed tools) in session")

    # Compute Total Behavioral Score
    total_score = min(100, sum(component_breakdown.values()))

    # Map to Policy Decision
    if total_score <= THRESHOLD_ALLOW:
        decision = Decision.ALLOW.value
    elif total_score <= THRESHOLD_MONITOR:
        decision = Decision.MONITOR.value
    elif total_score <= THRESHOLD_CONFIRM:
        decision = Decision.CONFIRM.value
    else:
        decision = Decision.BLOCK.value

    explanation = "; ".join(reasons) if reasons else "Normal behavioral profile observed."

    return BehavioralAssessment(
        risk_score=total_score,
        decision=decision,
        indicators=triggered_indicators,
        explanation=explanation,
        component_breakdown=component_breakdown,
        contributing_event_ids=list(set(contributing_event_ids)),
    )
