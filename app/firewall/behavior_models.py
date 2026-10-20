from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class BehavioralEventType(str, Enum):
    USER_REQUEST = "user_request"
    INPUT_INSPECTED = "input_inspected"
    TOOL_REQUESTED = "tool_requested"
    TOOL_AUTHORIZED = "tool_authorized"
    TOOL_DENIED = "tool_denied"
    TOOL_EXECUTED = "tool_executed"
    TOOL_RESULT_RECEIVED = "tool_result_received"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_APPROVED = "confirmation_approved"
    OUTPUT_PREPARED = "output_prepared"


class UserIntent(str, Enum):
    GENERAL_INFORMATION = "general_information"
    CALCULATION = "calculation"
    PUBLIC_RESEARCH = "public_research"
    DATABASE_LOOKUP = "database_lookup"
    FILE_ACCESS = "file_access"
    COMMUNICATION = "communication"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class BehavioralIndicator(str, Enum):
    ACTION_OUTSIDE_REQUEST_SCOPE = "action_outside_request_scope"
    SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION = "sensitive_resource_without_justification"
    UNEXPECTED_PRIVILEGE_ESCALATION = "unexpected_privilege_escalation"
    SUSPICIOUS_ACTION_SEQUENCE = "suspicious_action_sequence"
    REPEATED_DENIED_ACTIONS = "repeated_denied_actions"
    UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION = "untrusted_content_followed_by_sensitive_action"
    SENSITIVE_DATA_MOVEMENT = "sensitive_data_movement"
    UNUSUAL_TOOL_CHAIN = "unusual_tool_chain"
    EXCESSIVE_TOOL_ACTIVITY = "excessive_tool_activity"


class BehavioralEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    session_id: str
    timestamp: str
    event_type: BehavioralEventType
    user_intent: Optional[UserIntent] = None
    tool_name: Optional[str] = None
    tool_action: Optional[str] = None
    risk_score: int = 0
    policy_decision: Optional[str] = None
    required_permission: Optional[str] = None
    data_sensitivity: Optional[DataSensitivity] = None
    execution_outcome: Optional[str] = None
    security_indicators: List[str] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = None


class BehavioralAssessment(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    decision: str
    indicators: List[str] = Field(default_factory=list)
    explanation: str
    component_breakdown: Dict[str, int] = Field(default_factory=dict)
    contributing_event_ids: List[str] = Field(default_factory=list)
