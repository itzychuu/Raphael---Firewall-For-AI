import datetime
import logging
import uuid
from typing import Any, Dict
import os
import secrets
import requests
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.agent.agent import OLLAMA_URL, run_agent_loop
from app.firewall.audit import get_audit_events, log_audit_event
from app.firewall.behavior_models import BehavioralEvent, BehavioralEventType
from app.firewall.confirmation import canonical_action_id, get_challenge_info, validate_and_consume_challenge
from app.firewall.dlp_detector import scan_data_for_dlp
from app.firewall.gateway import inspect_input
from app.firewall.output_firewall import inspect_output
from app.firewall.redaction import redact_structured_data
from app.firewall.session_history import session_history
from app.firewall.tool_firewall import tool_registry
from app.models.schemas import (
    AuditEventType,
    ChatRequest,
    ChatResponse,
    Decision,
    HealthResponse,
    InspectRequest,
    InspectResponse,
    OutputInspectRequest,
    OutputInspectResponse,
    SecurityContext,
)

logger = logging.getLogger("raphael.api")

app = FastAPI(
    title="RAPHAEL Security Gateway",
    description="Runtime security gateway and controlled execution boundary for AI agents.",
    version="0.3.0",
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "error": "Request validation failed",
            "details": [
                {"field": ".".join(str(loc) for loc in err.get("loc", [])), "message": err.get("msg")}
                for err in exc.errors()
            ],
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error": "An internal error occurred while processing the request.",
        },
    )


@app.get("/health", response_model=HealthResponse)
def health_check():
    """Service health and external dependency check."""
    dependencies: Dict[str, Any] = {}

    # Verify Ollama service readiness
    ollama_base = OLLAMA_URL.replace("/api/chat", "")
    try:
        resp = requests.get(f"{ollama_base}/api/tags", timeout=1.5)
        if resp.status_code == 200:
            dependencies["ollama"] = {
                "status": "ready",
                "endpoint": OLLAMA_URL,
            }
        else:
            dependencies["ollama"] = {
                "status": "degraded",
                "endpoint": OLLAMA_URL,
                "http_status": resp.status_code,
            }
    except Exception:
        dependencies["ollama"] = {
            "status": "unreachable",
            "endpoint": OLLAMA_URL,
            "error": "Connection timed out or refused",
        }

    is_healthy = dependencies["ollama"]["status"] == "ready"
    overall_status = "healthy" if is_healthy else "degraded"

    return HealthResponse(
        status=overall_status,
        service="RAPHAEL Security Gateway",
        version="0.3.0",
        dependencies=dependencies,
    )


@app.post("/inspect", response_model=InspectResponse)
def inspect_endpoint(payload: InspectRequest):
    """Inspect input for prompt injection and security risks without invoking LLM or tools."""
    corr_id = str(uuid.uuid4())
    result = inspect_input(payload.message, correlation_id=corr_id)

    return InspectResponse(
        detected=result["detected"],
        risk=result["risk"],
        decision=Decision(result["decision"]),
        reason=result["reason"],
        matches=result["matches"],
    )


@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(payload: ChatRequest):
    """Guarded chat execution pipeline.

    1. Input validation & prompt injection analysis via Input Firewall.
    2. Policy gating (BLOCK / CONFIRM / ALLOW).
    3. Controlled agent execution through Central Tool Firewall.
    4. Structured auditing and safe response generation.
    """
    corr_id = payload.correlation_id or str(uuid.uuid4())

    # Step 1: Input Firewall Inspection
    inspection = inspect_input(payload.message, correlation_id=corr_id)
    input_decision = Decision(inspection["decision"])
    risk_score = inspection["risk"]

    session_history.add_event(
        BehavioralEvent(
            event_id=str(uuid.uuid4()),
            session_id=corr_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            event_type=BehavioralEventType.INPUT_INSPECTED,
            risk_score=risk_score,
            policy_decision=input_decision.value,
        )
    )

    # Step 2: Enforce Input Policy Decisions
    if input_decision == Decision.BLOCK:
        return ChatResponse(
            status="blocked",
            response="Your request was blocked by the input security firewall.",
            decision=Decision.BLOCK,
            risk=risk_score,
            tool_calls=[],
            audit_id=corr_id,
            reason=inspection["reason"] or "Prompt injection detected",
        )

    if input_decision == Decision.CONFIRM:
        return ChatResponse(
            status="confirmation_required",
            response="This input requires explicit security confirmation before execution.",
            decision=Decision.CONFIRM,
            risk=risk_score,
            tool_calls=[],
            audit_id=corr_id,
            reason=inspection["reason"] or "Elevated risk input detected",
        )

    # Step 3: Prepare Security Context with Server-Verified Confirmations
    verified_confirmations = []
    verified_disclosures = []
    approved_action = None
    approved_parameters = None

    if payload.confirmation_token:
        challenge = get_challenge_info(payload.confirmation_token)
        if challenge and validate_and_consume_challenge(
            token=payload.confirmation_token,
            action=challenge.action,
            session_id=corr_id,
            parameters=challenge.parameters,
        ):
            approved_action = challenge.action
            approved_parameters = dict(challenge.parameters)
            if challenge.action == "disclose_confidential":
                res = challenge.parameters.get("resource")
                if res:
                    verified_disclosures.append(res)
            elif challenge.action == "send_email":
                recipient = challenge.parameters.get("recipient")
                message = challenge.parameters.get("message")
                if recipient and message:
                    reg = tool_registry.get("send_email")
                    try:
                        approved_parameters = reg.schema.model_validate(challenge.parameters).model_dump()
                    except Exception:
                        pass
                    action_id = canonical_action_id("send_email", approved_parameters)
                    verified_confirmations.append(action_id)
                else:
                    log_audit_event(
                        event_type=AuditEventType.SECURITY_ERROR,
                        policy_decision=Decision.BLOCK,
                        outcome="email_confirmation_missing_parameters",
                        risk_score=75,
                        correlation_id=corr_id,
                    )
            elif challenge.action.startswith("tool_result:"):
                verified_confirmations.append(challenge.action)
            else:
                reg = tool_registry.get(challenge.action)
                if reg:
                    try:
                        approved_parameters = reg.schema.model_validate(challenge.parameters).model_dump()
                    except Exception:
                        pass
                action_id = canonical_action_id(challenge.action, approved_parameters)
                verified_confirmations.append(action_id)

        else:
            masked_token = (payload.confirmation_token[:8] + "...") if payload.confirmation_token else "none"
            log_audit_event(
                event_type=AuditEventType.SECURITY_ERROR,
                policy_decision=Decision.BLOCK,
                outcome="invalid_or_replayed_confirmation_token",
                risk_score=75,
                correlation_id=corr_id,
                details={"provided_token": masked_token},
            )

    # Note: Client-supplied confirmed_actions are strictly rejected for confirmation bypass
    if payload.confirmed_actions:
        log_audit_event(
            event_type=AuditEventType.SECURITY_ERROR,
            policy_decision=Decision.BLOCK,
            outcome="untrusted_client_confirmed_actions_ignored",
            risk_score=70,
            correlation_id=corr_id,
            details={"ignored_actions": [str(a)[:50] for a in payload.confirmed_actions]},
        )

    security_context = SecurityContext(
        confirmed_actions=verified_confirmations,
        confirmed_disclosures=verified_disclosures,
    )

    # Step 4: Controlled Agent Execution
    try:
        agent_result = run_agent_loop(
            user_input=payload.message,
            security_context=security_context,
            correlation_id=corr_id,
            approved_action=approved_action,
            approved_parameters=approved_parameters,
        )
    except Exception as exc:
        logger.error(f"Error during agent execution: {exc}")
        log_audit_event(
            event_type=AuditEventType.SECURITY_ERROR,
            policy_decision=Decision.BLOCK,
            outcome="agent_failure",
            risk_score=70,
            correlation_id=corr_id,
            details={"error": "Agent execution failed"},
        )
        return ChatResponse(
            status="error",
            response="An unexpected error occurred during execution.",
            decision=Decision.BLOCK,
            risk=70,
            tool_calls=[],
            audit_id=corr_id,
            reason="Agent execution failure",
        )

    # Step 5: Format and sanitize response based on agent outcome
    agent_status = agent_result.get("status", "success")
    decision_str = agent_result.get("decision", Decision.ALLOW.value)
    final_decision = Decision(decision_str) if decision_str in Decision._value2member_map_ else Decision.ALLOW

    # Sanitize tool_calls arguments so sensitive data (SSNs, credentials) never leaks in auxiliary fields
    sanitized_tool_calls = []
    for tc in agent_result.get("tool_calls", []):
        tc_copy = dict(tc)
        if "arguments" in tc_copy and isinstance(tc_copy["arguments"], dict):
            _, arg_findings = scan_data_for_dlp(tc_copy["arguments"])
            if arg_findings:
                tc_copy["arguments"] = redact_structured_data(tc_copy["arguments"], arg_findings)
        sanitized_tool_calls.append(tc_copy)

    return ChatResponse(
        status=agent_status,
        response=agent_result.get("response", ""),
        decision=final_decision,
        risk=agent_result.get("risk", risk_score),
        tool_calls=sanitized_tool_calls,
        audit_id=corr_id,
        reason=agent_result.get("error") or agent_result.get("reason"),
        confirmation_token=agent_result.get("confirmation_token"),
        output_inspection=agent_result.get("output_inspection"),
    )


@app.get("/behavior/session/{session_id}")
def get_session_behavior(session_id: str, request: Request):
    """Retrieve tracked behavioral events for a specific session (requires research/admin authorization)."""
    expected_token = os.getenv("RAPHAEL_RESEARCH_TOKEN")
    if not expected_token:
        # Fail-closed: when no research token is configured, the endpoint is disabled
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Research endpoint disabled: RAPHAEL_RESEARCH_TOKEN is not configured.",
        )

    auth_header = request.headers.get("X-RAPHAEL-RESEARCH-TOKEN") or request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Missing research authorization token.",
        )

    candidate = auth_header[7:].strip() if auth_header.startswith("Bearer ") else auth_header.strip()
    if not secrets.compare_digest(candidate, expected_token.strip()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Invalid research token.",
        )

    events = session_history.get_session_events(session_id)
    return {
        "session_id": session_id,
        "event_count": len(events),
        "events": [event.model_dump() for event in events],
    }


@app.post("/inspect-output", response_model=OutputInspectResponse)
def inspect_output_endpoint(payload: OutputInspectRequest):
    """Inspect text content for sensitive data and evaluate disclosure policy.
    Public endpoint strictly enforces destination='api_client'; client-controlled destinations are ignored.
    This endpoint operates strictly as an unprivileged, stateless detector without provenance or authorization grants.
    """
    result = inspect_output(
        content=payload.content,
        security_context=SecurityContext(),  # Strictly unprivileged default context
        destination="api_client",             # Strictly public client destination
        provenance=None,                      # Client-supplied provenance is untrusted
    )
    return OutputInspectResponse(
        inspection_id=result.inspection_id,
        destination=result.destination,
        decision=result.decision,
        risk_score=result.risk_score,
        detected_sensitivity=result.detected_sensitivity,
        findings_count=len(result.findings),
        explanation=result.explanation,
        redacted_content=result.redacted_content,
        release_permitted=result.release_permitted,
    )
