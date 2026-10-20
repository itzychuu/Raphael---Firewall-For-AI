from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
import re


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    CONFIRM = "CONFIRM"
    BLOCK = "BLOCK"


class ToolExecutionStatus(str, Enum):
    SUCCESS = "success"
    VALIDATION_ERROR = "validation_error"
    UNAUTHORIZED = "unauthorized"
    CONFIRMATION_REQUIRED = "confirmation_required"
    EXECUTION_ERROR = "execution_error"
    BLOCKED = "blocked"


class AuditEventType(str, Enum):
    INPUT_INSPECTION = "input_inspection"
    INPUT_BLOCKED = "input_blocked"
    INPUT_CONFIRM = "input_confirm"
    TOOL_AUTHORIZATION = "tool_authorization"
    TOOL_EXECUTION = "tool_execution"
    TOOL_BLOCKED = "tool_blocked"
    TOOL_CONFIRM_REQUIRED = "tool_confirm_required"
    TOOL_VALIDATION_ERROR = "tool_validation_error"
    AGENT_RUN = "agent_run"
    SECURITY_ERROR = "security_error"


class SecurityContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str = "default_user"
    role: str = "operator"
    permissions: List[str] = Field(
        default_factory=lambda: [
            "tools:calculate",
            "tools:web_search",
            "tools:database_read",
            "tools:file_read",
            "tools:email_send",
        ]
    )
    confirmed_actions: List[str] = Field(default_factory=list)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions or "*" in self.permissions

    def is_action_confirmed(self, action_id: str) -> bool:
        return action_id in self.confirmed_actions or "*" in self.confirmed_actions


# Tool Argument Schemas
class CalculatorArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expression: str = Field(..., min_length=1, max_length=100)

    @field_validator("expression")
    @classmethod
    def validate_expression(cls, v: str) -> str:
        allowed = "0123456789+-*/(). "
        if not all(c in allowed for c in v):
            raise ValueError("Expression contains disallowed characters")
        if "__" in v or "import" in v.lower() or "eval" in v.lower():
            raise ValueError("Expression contains unsafe keywords")
        return v.strip()


class WebSearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(..., min_length=1, max_length=200)

    @field_validator("query")
    @classmethod
    def clean_query(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Search query cannot be empty")
        return cleaned


class DatabaseReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    employee_id: str = Field(..., min_length=1, max_length=50)

    @field_validator("employee_id")
    @classmethod
    def validate_employee_id(cls, v: str) -> str:
        cleaned = v.strip()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", cleaned):
            raise ValueError("Invalid employee_id format: must be alphanumeric, underscores or hyphens")
        return cleaned


class FileReaderArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(..., min_length=1, max_length=100)

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        cleaned = v.strip()
        # Reject path traversal, absolute paths, backslashes, directory separators, null bytes
        if ".." in cleaned or "/" in cleaned or "\\" in cleaned or "\x00" in cleaned or ":" in cleaned:
            raise ValueError("Path traversal or nested directory paths are strictly forbidden")
        if not re.match(r"^[a-zA-Z0-9_\-\.]+\.txt$", cleaned):
            raise ValueError("Only .txt files with alphanumeric names are permitted")
        return cleaned


class SendEmailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipient: str = Field(..., min_length=3, max_length=100)
    message: str = Field(..., min_length=1, max_length=2000)
    subject: Optional[str] = Field(default="Notification", max_length=200)

    @field_validator("recipient")
    @classmethod
    def validate_recipient(cls, v: str) -> str:
        cleaned = v.strip()
        # Strict email format check
        email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_pattern, cleaned):
            raise ValueError("Invalid email address format")
        return cleaned


# Tool Execution Models
class ToolExecutionResult(BaseModel):
    tool: str
    status: ToolExecutionStatus
    decision: Decision
    risk: int = 0
    result: Optional[Any] = None
    error: Optional[str] = None
    reason: Optional[str] = None


# Audit Event Model
class AuditEvent(BaseModel):
    audit_id: str
    timestamp: str
    event_type: AuditEventType
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    tool_name: Optional[str] = None
    risk_score: int = 0
    policy_decision: Decision
    outcome: str
    details: Optional[Dict[str, Any]] = None


# API Models
class InspectRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)


class InspectResponse(BaseModel):
    detected: bool
    risk: int
    decision: Decision
    reason: Optional[str] = None
    matches: List[str] = Field(default_factory=list)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000)
    confirmed_actions: Optional[List[str]] = Field(default_factory=list)
    correlation_id: Optional[str] = None


class ChatResponse(BaseModel):
    status: str
    response: Optional[str] = None
    decision: Decision
    risk: int = 0
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    audit_id: Optional[str] = None
    reason: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    service: str = "RAPHAEL Gateway"
    version: str = "0.3.0"
    dependencies: Dict[str, Any]
