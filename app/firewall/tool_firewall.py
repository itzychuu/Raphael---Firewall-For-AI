import datetime
import re
import uuid
from typing import Any, Callable, Dict, Optional, Type
from pydantic import BaseModel, ValidationError

from app.firewall.audit import log_audit_event
from app.firewall.behavior_models import (
    BehavioralEvent,
    BehavioralEventType,
    DataSensitivity,
    UserIntent,
)
from app.firewall.behavioral_engine import assess_behavior
from app.firewall.sensitivity import classify_resource_sensitivity
from app.firewall.confirmation import canonical_action_id
from app.firewall.session_history import session_history
from app.models.schemas import (
    AuditEventType,
    CalculatorArgs,
    DatabaseReadArgs,
    Decision,
    FileReaderArgs,
    SecurityContext,
    SendEmailArgs,
    ToolExecutionResult,
    ToolExecutionStatus,
    WebSearchArgs,
)
from app.tools.calculator import calculator
from app.tools.database import database_read
from app.tools.email import send_email
from app.tools.file_reader import file_read
from app.tools.web_search import web_search


class ToolRegistration:
    def __init__(
        self,
        name: str,
        func: Callable[..., Any],
        schema: Type[BaseModel],
        required_permission: str,
        default_risk: int,
        default_decision: Decision,
        description: str,
    ):
        self.name = name
        self.func = func
        self.schema = schema
        self.required_permission = required_permission
        self.default_risk = default_risk
        self.default_decision = default_decision
        self.description = description


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolRegistration] = {}
        self._register_defaults()

    def _register_defaults(self):
        self.register(
            ToolRegistration(
                name="calculator",
                func=calculator,
                schema=CalculatorArgs,
                required_permission="tools:calculate",
                default_risk=10,
                default_decision=Decision.ALLOW,
                description="Safely evaluate mathematical arithmetic expressions.",
            )
        )
        self.register(
            ToolRegistration(
                name="web_search",
                func=web_search,
                schema=WebSearchArgs,
                required_permission="tools:web_search",
                default_risk=15,
                default_decision=Decision.ALLOW,
                description="Search knowledge base for relevant facts.",
            )
        )
        self.register(
            ToolRegistration(
                name="database_read",
                func=database_read,
                schema=DatabaseReadArgs,
                required_permission="tools:database_read",
                default_risk=40,
                default_decision=Decision.MONITOR,
                description="Lookup internal employee details by ID.",
            )
        )
        self.register(
            ToolRegistration(
                name="file_read",
                func=file_read,
                schema=FileReaderArgs,
                required_permission="tools:file_read",
                default_risk=20,
                default_decision=Decision.ALLOW,
                description="Read pre-approved mock text files.",
            )
        )
        self.register(
            ToolRegistration(
                name="send_email",
                func=send_email,
                schema=SendEmailArgs,
                required_permission="tools:email_send",
                default_risk=65,
                default_decision=Decision.CONFIRM,
                description="Send outbound simulated email messages.",
            )
        )

    def register(self, registration: ToolRegistration) -> None:
        self._tools[registration.name] = registration

    def get(self, name: str) -> Optional[ToolRegistration]:
        return self._tools.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        return {
            name: {
                "description": reg.description,
                "required_permission": reg.required_permission,
                "default_decision": reg.default_decision.value,
                "schema": reg.schema.model_json_schema(),
            }
            for name, reg in self._tools.items()
        }


# Global tool registry instance
tool_registry = ToolRegistry()


def evaluate_tool_policy(
    reg: ToolRegistration,
    arguments: Dict[str, Any],
    security_context: SecurityContext,
) -> tuple[Decision, int, Optional[str]]:
    """Determine the Phase 3 static policy decision and risk for a specific tool call and context."""
    risk = reg.default_risk
    decision = reg.default_decision
    reason = None

    # Context-aware policies
    if reg.name == "file_read":
        filename = arguments.get("filename", "")
        if "confidential" in filename.lower():
            action_id = canonical_action_id("file_read", arguments)
            # Security invariant: Generic 'file_read' and filename-only confirmations are strictly rejected.
            # Strict binding to exact validated parameters (canonical_action_id) is enforced.
            if security_context.is_action_confirmed(action_id):
                decision = Decision.MONITOR
                risk = 35
                reason = "Access to confidential file confirmed by user authorization"
            else:
                risk = 65
                decision = Decision.CONFIRM
                reason = "Access to confidential file requires explicit confirmation"

    elif reg.name == "send_email":
        action_id = canonical_action_id("send_email", arguments)
        # Security invariant: Generic 'send_email' and recipient-only authorizations are strictly rejected.
        # Strict binding to exact validated parameters (canonical_action_id) is enforced.
        if security_context.is_action_confirmed(action_id):
            decision = Decision.MONITOR
            risk = 35
            reason = "Outbound email confirmed by user authorization"
        else:
            decision = Decision.CONFIRM
            risk = 65
            reason = "Simulated outbound email requires explicit confirmation before dispatch"

    return decision, risk, reason


DECISION_SEVERITY = {
    Decision.ALLOW: 0,
    Decision.MONITOR: 1,
    Decision.CONFIRM: 2,
    Decision.BLOCK: 3,
}


def combine_decisions(
    phase3_decision: Decision,
    phase3_risk: int,
    phase3_reason: Optional[str],
    behavioral_decision: Decision,
    behavioral_risk: int,
    behavioral_reason: Optional[str],
) -> tuple[Decision, int, str]:
    """Combine Phase 3 authorization decisions with Phase 4 Behavioral Risk Assessment.

    Enforces critical security invariants:
    - Phase 3 BLOCK can NEVER be downgraded.
    - Phase 3 CONFIRM can NEVER be downgraded to ALLOW or MONITOR.
    - If behavioral risk recommends a more restrictive decision, escalate to the more restrictive one.
    - Final risk is the maximum of static risk and behavioral risk.
    """
    final_risk = max(phase3_risk, behavioral_risk)

    sev_p3 = DECISION_SEVERITY[phase3_decision]
    sev_beh = DECISION_SEVERITY[behavioral_decision]

    # Most restrictive decision wins
    if sev_beh > sev_p3:
        final_decision = behavioral_decision
    else:
        final_decision = phase3_decision

    # Invariant check: Phase 3 BLOCK cannot be lowered
    if phase3_decision == Decision.BLOCK:
        final_decision = Decision.BLOCK

    # Invariant check: Phase 3 CONFIRM cannot be lowered to ALLOW or MONITOR
    if phase3_decision == Decision.CONFIRM and final_decision in (Decision.ALLOW, Decision.MONITOR):
        final_decision = Decision.CONFIRM

    # Construct combined explanation
    reasons = [r for r in [phase3_reason, behavioral_reason] if r]
    final_reason = "; ".join(reasons) if reasons else "Policy enforced"

    return final_decision, final_risk, final_reason


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    security_context: Optional[SecurityContext] = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    user_intent: Optional[UserIntent] = None,
) -> ToolExecutionResult:
    """Central Tool Firewall Boundary with Behavioral Risk Engine Integration.

    1. Tool Registry Verification
    2. Least Privilege Authorization Check
    3. Strict Pydantic Argument Validation
    4. Phase 3 Static Policy Evaluation
    5. Phase 4 Behavioral Risk Assessment across Session History
    6. Policy Combination respecting Security Invariants
    7. Sandboxed Tool Execution and Session Event Recording
    """
    context = security_context or SecurityContext()
    sid = session_id or correlation_id or str(uuid.uuid4())
    now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Tool Registry Verification
    reg = tool_registry.get(tool_name)
    if not reg:
        log_audit_event(
            event_type=AuditEventType.TOOL_BLOCKED,
            policy_decision=Decision.BLOCK,
            outcome="rejected_unknown_tool",
            risk_score=90,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": f"Tool '{tool_name}' is not registered"},
        )
        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.TOOL_DENIED,
                tool_name=tool_name,
                risk_score=90,
                policy_decision=Decision.BLOCK.value,
                execution_outcome="rejected_unknown_tool",
            )
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.BLOCKED,
            decision=Decision.BLOCK,
            risk=90,
            error=f"Tool '{tool_name}' is not permitted or does not exist",
            reason="Unregistered tool",
        )

    # 2. Authorization / Least Privilege Check
    if not context.has_permission(reg.required_permission):
        log_audit_event(
            event_type=AuditEventType.TOOL_BLOCKED,
            policy_decision=Decision.BLOCK,
            outcome="permission_denied",
            risk_score=80,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={
                "required_permission": reg.required_permission,
                "user_permissions": context.permissions,
            },
        )
        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.TOOL_DENIED,
                tool_name=tool_name,
                risk_score=80,
                policy_decision=Decision.BLOCK.value,
                required_permission=reg.required_permission,
                execution_outcome="permission_denied",
            )
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.UNAUTHORIZED,
            decision=Decision.BLOCK,
            risk=80,
            error=f"Permission denied: missing '{reg.required_permission}'",
            reason="Insufficient privileges",
        )

    # 3. Argument Validation using Strict Schemas
    try:
        validated_args = reg.schema.model_validate(arguments).model_dump()
    except ValidationError as val_err:
        first_error = val_err.errors()[0]
        field_name = ".".join(str(loc) for loc in first_error.get("loc", []))
        error_msg = f"Argument validation failed for {field_name}: {first_error.get('msg')}"
        log_audit_event(
            event_type=AuditEventType.TOOL_VALIDATION_ERROR,
            policy_decision=Decision.BLOCK,
            outcome="validation_failed",
            risk_score=60,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"validation_errors": error_msg},
        )
        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.TOOL_DENIED,
                tool_name=tool_name,
                risk_score=60,
                policy_decision=Decision.BLOCK.value,
                execution_outcome="validation_failed",
            )
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.VALIDATION_ERROR,
            decision=Decision.BLOCK,
            risk=60,
            error=error_msg,
            reason="Argument schema validation failure",
        )
    except Exception:
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.VALIDATION_ERROR,
            decision=Decision.BLOCK,
            risk=60,
            error="Malformed tool arguments",
            reason="Argument validation failure",
        )

    # 4. Contextual Phase 3 Policy & Risk Evaluation
    phase3_decision, phase3_risk, phase3_reason = evaluate_tool_policy(reg, validated_args, context)

    # Determine Resource Sensitivity
    resource_sensitivity = classify_resource_sensitivity(tool_name, validated_args)

    # 5. Phase 4 Behavioral Risk Assessment
    prior_events = session_history.get_session_events(sid)

    # Deduce user intent from session history if not explicitly provided
    effective_intent = user_intent
    if not effective_intent:
        for ev in prior_events:
            if ev.event_type == BehavioralEventType.USER_REQUEST and ev.user_intent:
                effective_intent = ev.user_intent
                break
    if not effective_intent:
        effective_intent = UserIntent.UNKNOWN

    # Record TOOL_REQUESTED in session history
    session_history.add_event(
        BehavioralEvent(
            event_id=str(uuid.uuid4()),
            session_id=sid,
            timestamp=now_ts,
            event_type=BehavioralEventType.TOOL_REQUESTED,
            user_intent=effective_intent,
            tool_name=tool_name,
            tool_action=tool_name,
            required_permission=reg.required_permission,
            data_sensitivity=resource_sensitivity,
        )
    )

    try:
        behavioral_assessment = assess_behavior(
            tool_name=tool_name,
            arguments=validated_args,
            user_intent=effective_intent,
            session_events=prior_events,
            security_context=context,
        )
        beh_decision = Decision(behavioral_assessment.decision)
        beh_risk = behavioral_assessment.risk_score
        beh_reason = behavioral_assessment.explanation
        beh_dict = behavioral_assessment.model_dump()
    except Exception as exc:
        # Fail-safe policy: never fail open on behavioral assessment error
        log_audit_event(
            event_type=AuditEventType.SECURITY_ERROR,
            policy_decision=Decision.CONFIRM if resource_sensitivity != DataSensitivity.PUBLIC else Decision.MONITOR,
            outcome="behavioral_engine_exception",
            risk_score=50,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"error": str(exc)},
        )
        beh_decision = Decision.CONFIRM if resource_sensitivity in (DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED) else Decision.MONITOR
        beh_risk = 50
        beh_reason = "Behavioral assessment encountered error; applying conservative fail-safe policy"
        beh_dict = {"error": "Behavioral assessment failed"}

    # 6. Combine Policy Decisions Respecting Invariants
    final_decision, final_risk, final_reason = combine_decisions(
        phase3_decision=phase3_decision,
        phase3_risk=phase3_risk,
        phase3_reason=phase3_reason,
        behavioral_decision=beh_decision,
        behavioral_risk=beh_risk,
        behavioral_reason=beh_reason,
    )

    # 7. Policy Enforcement
    if final_decision == Decision.BLOCK:
        log_audit_event(
            event_type=AuditEventType.TOOL_BLOCKED,
            policy_decision=Decision.BLOCK,
            outcome="blocked_by_policy",
            risk_score=final_risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": final_reason, "behavioral": beh_dict},
        )
        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.TOOL_DENIED,
                tool_name=tool_name,
                risk_score=final_risk,
                policy_decision=Decision.BLOCK.value,
                data_sensitivity=resource_sensitivity,
                execution_outcome="blocked_by_policy",
                security_indicators=beh_dict.get("indicators", []),
            )
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.BLOCKED,
            decision=Decision.BLOCK,
            risk=final_risk,
            error="Tool execution blocked by security policy",
            reason=final_reason,
            behavioral_assessment=beh_dict,
        )

    if final_decision == Decision.CONFIRM:
        safe_audit_args = dict(validated_args)
        if tool_name == "send_email" and "message" in safe_audit_args:
            safe_audit_args["message"] = f"[{len(str(safe_audit_args['message']))} chars redacted]"

        log_audit_event(
            event_type=AuditEventType.TOOL_CONFIRM_REQUIRED,
            policy_decision=Decision.CONFIRM,
            outcome="confirmation_required",
            risk_score=final_risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": final_reason, "arguments": safe_audit_args, "behavioral": beh_dict},
        )
        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.CONFIRMATION_REQUIRED,
                tool_name=tool_name,
                risk_score=final_risk,
                policy_decision=Decision.CONFIRM.value,
                data_sensitivity=resource_sensitivity,
                execution_outcome="confirmation_required",
                security_indicators=beh_dict.get("indicators", []),
            )
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.CONFIRMATION_REQUIRED,
            decision=Decision.CONFIRM,
            risk=final_risk,
            result=None,
            error=None,
            reason=final_reason,
            behavioral_assessment=beh_dict,
        )

    if final_decision == Decision.MONITOR:
        log_audit_event(
            event_type=AuditEventType.TOOL_AUTHORIZATION,
            policy_decision=Decision.MONITOR,
            outcome="monitored_execution_authorized",
            risk_score=final_risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": final_reason, "behavioral": beh_dict},
        )

    # Record TOOL_AUTHORIZED in session history
    session_history.add_event(
        BehavioralEvent(
            event_id=str(uuid.uuid4()),
            session_id=sid,
            timestamp=now_ts,
            event_type=BehavioralEventType.TOOL_AUTHORIZED,
            tool_name=tool_name,
            risk_score=final_risk,
            policy_decision=final_decision.value,
            data_sensitivity=resource_sensitivity,
        )
    )

    # 8. Safe Execution
    try:
        tool_output = reg.func(**validated_args)

        log_audit_event(
            event_type=AuditEventType.TOOL_EXECUTION,
            policy_decision=final_decision,
            outcome="success",
            risk_score=final_risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={
                "status": tool_output.get("status") if isinstance(tool_output, dict) else "completed",
                "behavioral_risk": beh_risk,
            },
        )

        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.TOOL_EXECUTED,
                tool_name=tool_name,
                risk_score=final_risk,
                policy_decision=final_decision.value,
                data_sensitivity=resource_sensitivity,
                execution_outcome="success",
            )
        )

        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.SUCCESS,
            decision=final_decision,
            risk=final_risk,
            result=tool_output,
            reason=final_reason,
            behavioral_assessment=beh_dict,
        )

    except Exception as exc:
        log_audit_event(
            event_type=AuditEventType.SECURITY_ERROR,
            policy_decision=Decision.BLOCK,
            outcome="tool_exception",
            risk_score=75,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"error_type": type(exc).__name__},
        )
        session_history.add_event(
            BehavioralEvent(
                event_id=str(uuid.uuid4()),
                session_id=sid,
                timestamp=now_ts,
                event_type=BehavioralEventType.TOOL_DENIED,
                tool_name=tool_name,
                risk_score=75,
                policy_decision=Decision.BLOCK.value,
                execution_outcome="tool_exception",
            )
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.EXECUTION_ERROR,
            decision=final_decision,
            risk=final_risk,
            error="Tool execution encountered an internal error",
            reason="Runtime exception in tool execution",
            behavioral_assessment=beh_dict,
        )
