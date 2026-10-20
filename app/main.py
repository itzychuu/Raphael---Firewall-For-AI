import logging
import uuid
from typing import Any, Dict
import requests
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.agent.agent import OLLAMA_URL, run_agent_loop
from app.firewall.audit import get_audit_events, log_audit_event
from app.firewall.gateway import inspect_input
from app.models.schemas import (
    AuditEventType,
    ChatRequest,
    ChatResponse,
    Decision,
    HealthResponse,
    InspectRequest,
    InspectResponse,
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

    # Step 3: Prepare Security Context
    security_context = SecurityContext(
        confirmed_actions=payload.confirmed_actions or [],
    )

    # Step 4: Controlled Agent Execution
    try:
        agent_result = run_agent_loop(
            user_input=payload.message,
            security_context=security_context,
            correlation_id=corr_id,
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

    # Step 5: Format response based on agent outcome
    agent_status = agent_result.get("status", "success")
    decision_str = agent_result.get("decision", Decision.ALLOW.value)
    final_decision = Decision(decision_str) if decision_str in Decision._value2member_map_ else Decision.ALLOW

    return ChatResponse(
        status=agent_status,
        response=agent_result.get("response", ""),
        decision=final_decision,
        risk=agent_result.get("risk", risk_score),
        tool_calls=agent_result.get("tool_calls", []),
        audit_id=corr_id,
        reason=agent_result.get("error") or agent_result.get("reason"),
    )
