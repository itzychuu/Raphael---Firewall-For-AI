import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from collections import deque

from app.models.schemas import AuditEvent, AuditEventType, Decision

logger = logging.getLogger("raphael.audit")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '{"time": "%(asctime)s", "level": "%(levelname)s", "audit": %(message)s}'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# In-memory audit event log buffer (bounded to prevent memory growth)
MAX_AUDIT_LOG_SIZE = 1000
_AUDIT_BUFFER: deque = deque(maxlen=MAX_AUDIT_LOG_SIZE)

# Patterns for sensitive data masking
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_PATTERN = re.compile(r"(?i)(api[_-]?key\s*[:=]\s*['\"]?)([\w-]+)(['\"]?)")
TOKEN_PATTERN = re.compile(r"(?i)(bearer\s+|token\s*[:=]\s*['\"]?)([\w\.-]+)(['\"]?)")


def mask_sensitive_data(data: Any) -> Any:
    """Recursively mask sensitive identifiers like SSNs, tokens, and API keys."""
    if isinstance(data, str):
        masked = SSN_PATTERN.sub("***-**-****", data)
        masked = API_KEY_PATTERN.sub(r"\1[REDACTED]\3", masked)
        masked = TOKEN_PATTERN.sub(r"\1[REDACTED]\3", masked)
        return masked
    elif isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(secret_term in k_lower for secret_term in ["ssn", "password", "secret", "token", "key"]):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = mask_sensitive_data(v)
        return cleaned
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data


def log_audit_event(
    event_type: AuditEventType,
    policy_decision: Decision,
    outcome: str,
    risk_score: int = 0,
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """Construct, sanitize, log, and store an audit event."""
    sanitized_details = mask_sensitive_data(details) if details else None

    event = AuditEvent(
        audit_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        correlation_id=correlation_id,
        user_id=user_id,
        tool_name=tool_name,
        risk_score=risk_score,
        policy_decision=policy_decision,
        outcome=outcome,
        details=sanitized_details,
    )

    _AUDIT_BUFFER.append(event)
    logger.info(event.model_dump_json())
    return event


def get_audit_events(limit: int = 100) -> List[AuditEvent]:
    """Retrieve the most recent audit events."""
    return list(_AUDIT_BUFFER)[-limit:]


def clear_audit_events() -> None:
    """Clear in-memory audit events (intended for test tear-downs)."""
    _AUDIT_BUFFER.clear()
