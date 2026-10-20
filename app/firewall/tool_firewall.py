import re
from typing import Any, Callable, Dict, Optional, Type
from pydantic import BaseModel, ValidationError

from app.firewall.audit import log_audit_event
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
    """Determine the policy decision and risk for a specific tool call and context."""
    risk = reg.default_risk
    decision = reg.default_decision
    reason = None

    # Context-aware policies
    if reg.name == "file_read":
        filename = arguments.get("filename", "")
        if "confidential" in filename.lower():
            risk = 65
            decision = Decision.CONFIRM
            reason = "Access to confidential file requires explicit confirmation"

    elif reg.name == "send_email":
        action_key = "send_email"
        recipient = arguments.get("recipient", "")
        if security_context.is_action_confirmed(action_key) or security_context.is_action_confirmed(f"send_email:{recipient}"):
            decision = Decision.MONITOR
            risk = 35
            reason = "Outbound email confirmed by user authorization"
        else:
            decision = Decision.CONFIRM
            risk = 65
            reason = "Simulated outbound email requires explicit confirmation before dispatch"

    return decision, risk, reason


def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    security_context: Optional[SecurityContext] = None,
    correlation_id: Optional[str] = None,
) -> ToolExecutionResult:
    """Central Tool Firewall Boundary.

    Enforces tool existence, argument validation, least privilege authorization,
    risk policy, confirmation gates, and safe execution.
    """
    context = security_context or SecurityContext()

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

    # 4. Contextual Policy and Risk Evaluation
    decision, risk, policy_reason = evaluate_tool_policy(reg, validated_args, context)

    # 5. Policy Decision Enforcement
    if decision == Decision.BLOCK:
        log_audit_event(
            event_type=AuditEventType.TOOL_BLOCKED,
            policy_decision=Decision.BLOCK,
            outcome="blocked_by_policy",
            risk_score=risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": policy_reason},
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.BLOCKED,
            decision=Decision.BLOCK,
            risk=risk,
            error="Tool execution blocked by security policy",
            reason=policy_reason,
        )

    if decision == Decision.CONFIRM:
        log_audit_event(
            event_type=AuditEventType.TOOL_CONFIRM_REQUIRED,
            policy_decision=Decision.CONFIRM,
            outcome="confirmation_required",
            risk_score=risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": policy_reason, "arguments": validated_args},
        )
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.CONFIRMATION_REQUIRED,
            decision=Decision.CONFIRM,
            risk=risk,
            result=None,
            error=None,
            reason=policy_reason or "Action requires explicit user confirmation before execution",
        )

    if decision == Decision.MONITOR:
        log_audit_event(
            event_type=AuditEventType.TOOL_AUTHORIZATION,
            policy_decision=Decision.MONITOR,
            outcome="monitored_execution_authorized",
            risk_score=risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"reason": policy_reason},
        )

    # 6. Safe Execution
    try:
        # Adapt arguments to underlying tool functions
        if tool_name == "send_email":
            # Underlying send_email takes recipient, message
            tool_output = reg.func(
                recipient=validated_args["recipient"],
                message=validated_args["message"],
            )
        else:
            tool_output = reg.func(**validated_args)

        # Audit successful execution
        log_audit_event(
            event_type=AuditEventType.TOOL_EXECUTION,
            policy_decision=decision,
            outcome="success",
            risk_score=risk,
            correlation_id=correlation_id,
            user_id=context.user_id,
            tool_name=tool_name,
            details={"status": tool_output.get("status") if isinstance(tool_output, dict) else "completed"},
        )

        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.SUCCESS,
            decision=decision,
            risk=risk,
            result=tool_output,
            reason=policy_reason,
        )

    except Exception as exc:
        # Prevent internal details / stack traces from leaking
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
        return ToolExecutionResult(
            tool=tool_name,
            status=ToolExecutionStatus.EXECUTION_ERROR,
            decision=decision,
            risk=risk,
            error="Tool execution encountered an internal error",
            reason="Runtime exception in tool execution",
        )
