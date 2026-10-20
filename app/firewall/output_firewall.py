import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Set

from app.firewall.audit import log_audit_event
from app.firewall.behavior_models import DataSensitivity
from app.firewall.data_provenance import SENSITIVITY_HIERARCHY, create_tool_provenance
from app.firewall.dlp_detector import scan_data_for_dlp
from app.firewall.redaction import redact_structured_data
from app.models.schemas import (
    AuditEventType,
    DataProvenance,
    Decision,
    DLPFinding,
    DLPFindingCategory,
    OutputDecision,
    OutputInspectionResult,
    SecurityContext,
)

logger = logging.getLogger("raphael.output_firewall")


def determine_highest_sensitivity(findings: List[DLPFinding], provenance: Optional[DataProvenance]) -> str:
    """Determine highest sensitivity level from DLP findings and provenance."""
    highest_rank = 0
    highest_level = DataSensitivity.PUBLIC.value

    if provenance:
        highest_rank = SENSITIVITY_HIERARCHY.get(provenance.sensitivity, 0)
        highest_level = provenance.sensitivity

    for finding in findings:
        rank = SENSITIVITY_HIERARCHY.get(finding.sensitivity, 0)
        if rank > highest_rank:
            highest_rank = rank
            highest_level = finding.sensitivity

    return highest_level


def evaluate_disclosure_policy(
    highest_sensitivity: str,
    findings: List[DLPFinding],
    security_context: SecurityContext,
    destination: str,
    provenance: Optional[DataProvenance] = None,
) -> tuple[OutputDecision, int, str, bool, Set[DLPFindingCategory]]:
    """Determine disclosure decision and whether redaction or blocking is required."""
    categories_to_redact: Set[DLPFindingCategory] = set()

    # 1. Agent Context Destination (feeding tool results to LLM)
    if destination == "agent_context":
        restricted_findings = [f for f in findings if f.sensitivity == DataSensitivity.RESTRICTED.value]
        if restricted_findings:
            # Restricted secrets (SSN, API keys, passwords, private keys) must NEVER enter LLM context raw
            for f in restricted_findings:
                categories_to_redact.add(f.category)
            return (
                OutputDecision.REDACT,
                45,
                "Restricted credentials/SSNs masked before entering LLM context",
                True,
                categories_to_redact,
            )
        return (
            OutputDecision.ALLOW,
            0,
            "Tool result permitted for agent reasoning context",
            True,
            categories_to_redact,
        )

    # 2. User / API Client Destination
    # Check for RESTRICTED findings in output
    restricted_findings = [f for f in findings if f.sensitivity == DataSensitivity.RESTRICTED.value]
    if restricted_findings and not security_context.has_permission("disclose:restricted"):
        for f in restricted_findings:
            categories_to_redact.add(f.category)

    # Check for CONFIDENTIAL findings in output
    confidential_findings = [f for f in findings if f.sensitivity == DataSensitivity.CONFIDENTIAL.value]
    if confidential_findings and not security_context.has_permission("disclose:confidential"):
        for f in confidential_findings:
            categories_to_redact.add(f.category)

    # If redactions are required due to missing disclosure permissions
    if categories_to_redact:
        return (
            OutputDecision.REDACT,
            60,
            "Sensitive data detected and redacted before client delivery",
            True,
            categories_to_redact,
        )

    # When no exact regex findings were detected, check if output derives from sensitive provenance
    if highest_sensitivity == DataSensitivity.RESTRICTED.value and not security_context.has_permission("disclose:restricted"):
        return (
            OutputDecision.BLOCK,
            85,
            "Response derives from restricted source data and cannot be safely redacted without disclosure authorization",
            False,
            set(),
        )

    if highest_sensitivity == DataSensitivity.CONFIDENTIAL.value:
        resource_name = provenance.source_resource if provenance and provenance.source_resource else "confidential_source"
        if not security_context.has_permission("disclose:confidential") and not security_context.is_disclosure_confirmed(resource_name):
            return (
                OutputDecision.CONFIRM,
                65,
                f"Disclosure of content derived from confidential source ('{resource_name}') requires explicit confirmation",
                False,
                set(),
            )

    return (
        OutputDecision.ALLOW,
        0,
        "Output authorized for client release",
        True,
        set(),
    )


def inspect_output(
    content: Any,
    security_context: Optional[SecurityContext] = None,
    provenance: Optional[DataProvenance] = None,
    destination: str = "api_client",
    session_id: Optional[str] = None,
) -> OutputInspectionResult:
    """Central Output Firewall Boundary.

    1. Scans output for sensitive data using deterministic DLP.
    2. Correlates findings with Data Provenance and destination.
    3. Evaluates authorization-aware disclosure policies.
    4. Applies deterministic redaction or blocking.
    5. Audits output events and enforces fail-closed execution.
    """
    context = security_context or SecurityContext()
    inspection_id = str(uuid.uuid4())

    try:
        # Step 1: DLP Scan
        serialized_text, findings = scan_data_for_dlp(content)

        # Step 2: Determine Sensitivity
        highest_sens = determine_highest_sensitivity(findings, provenance)

        # Step 3: Evaluate Disclosure Policy
        decision, risk, explanation, release_permitted, categories_to_redact = evaluate_disclosure_policy(
            highest_sensitivity=highest_sens,
            findings=findings,
            security_context=context,
            destination=destination,
            provenance=provenance,
        )

        # Step 4: Redaction Application
        redacted_content = None
        if decision == OutputDecision.REDACT:
            redacted_content = redact_structured_data(
                data=content,
                findings=findings,
                categories_to_redact=categories_to_redact,
            )

        # Step 5: Audit Event Logging
        audit_event_type = AuditEventType.OUTPUT_INSPECTED
        if findings:
            audit_event_type = AuditEventType.SENSITIVE_DATA_DETECTED
        if decision == OutputDecision.REDACT:
            audit_event_type = AuditEventType.OUTPUT_REDACTED
        elif decision == OutputDecision.BLOCK:
            audit_event_type = AuditEventType.OUTPUT_BLOCKED
        elif decision == OutputDecision.CONFIRM:
            audit_event_type = AuditEventType.OUTPUT_CONFIRMATION_REQUIRED

        log_audit_event(
            event_type=audit_event_type,
            policy_decision=decision.value,
            outcome="inspected",
            risk_score=risk,
            correlation_id=session_id or (provenance.session_id if provenance else None),
            user_id=context.user_id,
            details={
                "inspection_id": inspection_id,
                "destination": destination,
                "highest_sensitivity": highest_sens,
                "findings_count": len(findings),
                "categories": list(set(f.category.value for f in findings)),
                "explanation": explanation,
                "release_permitted": release_permitted,
            },
        )

        return OutputInspectionResult(
            inspection_id=inspection_id,
            destination=destination,
            decision=decision,
            risk_score=risk,
            detected_sensitivity=highest_sens,
            findings=findings,
            explanation=explanation,
            redacted_content=redacted_content,
            provenance=provenance,
            release_permitted=release_permitted,
        )

    except Exception as exc:
        logger.error(f"Output firewall exception: {exc}")
        # Enforce fail-closed security invariant
        log_audit_event(
            event_type=AuditEventType.OUTPUT_BLOCKED,
            policy_decision=Decision.BLOCK.value,
            outcome="fail_closed_exception",
            risk_score=90,
            correlation_id=session_id,
            user_id=context.user_id,
            details={"error": "Output firewall runtime exception; content blocked"},
        )
        return OutputInspectionResult(
            inspection_id=inspection_id,
            destination=destination,
            decision=OutputDecision.BLOCK,
            risk_score=90,
            detected_sensitivity=DataSensitivity.RESTRICTED.value,
            findings=[],
            explanation="Output inspection encountered an error; content held fail-closed",
            redacted_content=None,
            provenance=provenance,
            release_permitted=False,
        )
