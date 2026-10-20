import threading
import uuid
import pytest

from app.firewall.audit import clear_audit_events
from app.firewall.behavior_models import (
    BehavioralEvent,
    BehavioralEventType,
    BehavioralIndicator,
    DataSensitivity,
    UserIntent,
)
from app.firewall.behavioral_engine import assess_behavior
from app.firewall.intent import classify_intent, is_tool_justified_for_intent
from app.firewall.sensitivity import classify_resource_sensitivity
from app.firewall.session_history import SessionHistoryManager, session_history
from app.firewall.tool_firewall import execute_tool
from app.models.schemas import Decision, SecurityContext, ToolExecutionStatus


@pytest.fixture(autouse=True)
def clean_state():
    clear_audit_events()
    session_history.clear_all()
    yield
    clear_audit_events()
    session_history.clear_all()


# ============================================================================
# 1. Event & Session History Tests
# ============================================================================

def test_session_history_ordering_and_isolation():
    manager = SessionHistoryManager()
    session_a = "session_a"
    session_b = "session_b"

    event_a1 = BehavioralEvent(
        event_id="e1",
        session_id=session_a,
        timestamp="2026-10-20T10:00:00Z",
        event_type=BehavioralEventType.USER_REQUEST,
    )
    event_a2 = BehavioralEvent(
        event_id="e2",
        session_id=session_a,
        timestamp="2026-10-20T10:00:01Z",
        event_type=BehavioralEventType.TOOL_REQUESTED,
        tool_name="calculator",
    )
    event_b1 = BehavioralEvent(
        event_id="e3",
        session_id=session_b,
        timestamp="2026-10-20T10:00:02Z",
        event_type=BehavioralEventType.USER_REQUEST,
    )

    manager.add_event(event_a1)
    manager.add_event(event_a2)
    manager.add_event(event_b1)

    events_a = manager.get_session_events(session_a)
    events_b = manager.get_session_events(session_b)

    assert len(events_a) == 2
    assert events_a[0].event_id == "e1"
    assert events_a[1].event_id == "e2"

    assert len(events_b) == 1
    assert events_b[0].event_id == "e3"

    # Isolation check: session A cannot see session B's events
    assert all(e.session_id == session_a for e in events_a)
    assert all(e.session_id == session_b for e in events_b)


def test_session_history_bounded_limit():
    manager = SessionHistoryManager(max_events_per_session=5)
    sid = "bounded_session"

    for i in range(10):
        manager.add_event(
            BehavioralEvent(
                event_id=f"e_{i}",
                session_id=sid,
                timestamp=f"2026-10-20T10:00:0{i}Z",
                event_type=BehavioralEventType.TOOL_REQUESTED,
            )
        )

    events = manager.get_session_events(sid)
    assert len(events) == 5
    # Should contain the latest 5 events (e_5 through e_9)
    assert events[0].event_id == "e_5"
    assert events[-1].event_id == "e_9"


def test_session_history_clear_and_expiry():
    manager = SessionHistoryManager()
    sid = "temp_session"

    manager.add_event(
        BehavioralEvent(
            event_id="e1",
            session_id=sid,
            timestamp="2026-10-20T10:00:00Z",
            event_type=BehavioralEventType.USER_REQUEST,
        )
    )
    assert len(manager.get_session_events(sid)) == 1

    cleared = manager.clear_session(sid)
    assert cleared is True
    assert len(manager.get_session_events(sid)) == 0


def test_session_history_thread_safety():
    manager = SessionHistoryManager(max_events_per_session=100)
    sid = "concurrent_session"
    threads = []

    def add_events(start_idx: int):
        for i in range(25):
            manager.add_event(
                BehavioralEvent(
                    event_id=f"thread_{start_idx}_{i}",
                    session_id=sid,
                    timestamp="2026-10-20T10:00:00Z",
                    event_type=BehavioralEventType.TOOL_REQUESTED,
                )
            )

    for t_idx in range(4):
        t = threading.Thread(target=add_events, args=(t_idx,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    events = manager.get_session_events(sid)
    assert len(events) == 100


# ============================================================================
# 2. Intent & Sensitivity Tests
# ============================================================================

def test_intent_classification_taxonomy():
    cases = [
        ("Calculate 25 * 40", UserIntent.CALCULATION),
        ("What is the definition of machine learning?", UserIntent.PUBLIC_RESEARCH),
        ("Search python documentation", UserIntent.PUBLIC_RESEARCH),
        ("Look up employee salary in database", UserIntent.DATABASE_LOOKUP),
        ("Read the instructions file report", UserIntent.FILE_ACCESS),
        ("Send email to user@example.com", UserIntent.COMMUNICATION),
        ("Hello, who are you?", UserIntent.GENERAL_INFORMATION),
        ("xyzqwerty foobar 12345", UserIntent.UNKNOWN),
    ]

    for text, expected_intent in cases:
        intent, conf, _ = classify_intent(text)
        assert intent == expected_intent
        assert 0.0 <= conf <= 1.0


def test_intent_never_independently_grants_authorization():
    # Even if intent is DATABASE_LOOKUP, lacking permissions will reject execution
    restricted_context = SecurityContext(permissions=["tools:calculate"])
    sid = "intent_auth_test"

    result = execute_tool(
        "database_read",
        {"employee_id": "employee_001"},
        security_context=restricted_context,
        session_id=sid,
        user_intent=UserIntent.DATABASE_LOOKUP,
    )
    assert result.status == ToolExecutionStatus.UNAUTHORIZED
    assert result.decision == Decision.BLOCK


def test_resource_sensitivity_classification():
    assert classify_resource_sensitivity("calculator", {"expression": "2+2"}) == DataSensitivity.PUBLIC
    assert classify_resource_sensitivity("web_search", {"query": "python"}) == DataSensitivity.PUBLIC
    assert classify_resource_sensitivity("file_read", {"filename": "public_report.txt"}) == DataSensitivity.PUBLIC
    assert classify_resource_sensitivity("file_read", {"filename": "confidential.txt"}) == DataSensitivity.CONFIDENTIAL
    assert classify_resource_sensitivity("database_read", {"employee_id": "employee_001"}) == DataSensitivity.CONFIDENTIAL
    assert classify_resource_sensitivity("send_email", {"recipient": "a@b.com", "message": "SSN 999-12-3456"}) == DataSensitivity.RESTRICTED


# ============================================================================
# 3. Behavioral Detection & Attack Scenario Tests
# ============================================================================

def test_benign_single_tool_assessment():
    assessment = assess_behavior(
        tool_name="calculator",
        arguments={"expression": "100 / 4"},
        user_intent=UserIntent.CALCULATION,
        session_events=[],
    )
    assert assessment.risk_score <= 25
    assert assessment.decision == Decision.ALLOW.value
    assert len(assessment.indicators) == 0


def test_action_outside_request_scope():
    # User asked for calculation, but agent attempts to read employee database
    assessment = assess_behavior(
        tool_name="database_read",
        arguments={"employee_id": "employee_001"},
        user_intent=UserIntent.CALCULATION,
        session_events=[],
    )
    assert BehavioralIndicator.ACTION_OUTSIDE_REQUEST_SCOPE.value in assessment.indicators
    assert BehavioralIndicator.SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION.value in assessment.indicators
    assert assessment.risk_score >= 50
    assert assessment.decision in (Decision.CONFIRM.value, Decision.BLOCK.value)


def test_multi_step_exfiltration_sequence_detection():
    # Sequence: Read confidential file -> attempt to send email
    sid = "exfil_test_session"
    prior_events = [
        BehavioralEvent(
            event_id="e1",
            session_id=sid,
            timestamp="2026-10-20T10:00:00Z",
            event_type=BehavioralEventType.TOOL_EXECUTED,
            tool_name="file_read",
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            execution_outcome="success",
        )
    ]

    assessment = assess_behavior(
        tool_name="send_email",
        arguments={"recipient": "attacker@external.com", "message": "Exfiltrated secrets"},
        user_intent=UserIntent.FILE_ACCESS,
        session_events=prior_events,
    )

    assert BehavioralIndicator.SENSITIVE_DATA_MOVEMENT.value in assessment.indicators
    assert assessment.risk_score >= 65
    assert assessment.decision in (Decision.CONFIRM.value, Decision.BLOCK.value)
    assert "e1" in assessment.contributing_event_ids


def test_repeated_denied_actions_escalate_risk():
    sid = "denied_test_session"
    prior_events = [
        BehavioralEvent(
            event_id=f"denied_{i}",
            session_id=sid,
            timestamp=f"2026-10-20T10:00:0{i}Z",
            event_type=BehavioralEventType.TOOL_DENIED,
            tool_name="database_read",
            risk_score=80,
            policy_decision="BLOCK",
        )
        for i in range(2)
    ]

    assessment = assess_behavior(
        tool_name="calculator",
        arguments={"expression": "1 + 1"},
        user_intent=UserIntent.CALCULATION,
        session_events=prior_events,
    )

    assert BehavioralIndicator.REPEATED_DENIED_ACTIONS.value in assessment.indicators
    assert assessment.risk_score >= 40
    assert len(assessment.contributing_event_ids) == 2


def test_untrusted_content_followed_by_sensitive_action():
    # Sequence: Web search -> immediate query for confidential database employee
    sid = "untrusted_then_sensitive"
    prior_events = [
        BehavioralEvent(
            event_id="fetch_1",
            session_id=sid,
            timestamp="2026-10-20T10:00:00Z",
            event_type=BehavioralEventType.TOOL_EXECUTED,
            tool_name="web_search",
            data_sensitivity=DataSensitivity.PUBLIC,
            execution_outcome="success",
        )
    ]

    assessment = assess_behavior(
        tool_name="database_read",
        arguments={"employee_id": "employee_001"},
        user_intent=UserIntent.PUBLIC_RESEARCH,
        session_events=prior_events,
    )

    assert BehavioralIndicator.UNTRUSTED_CONTENT_FOLLOWED_BY_SENSITIVE_ACTION.value in assessment.indicators
    assert assessment.risk_score >= 50
    assert "fetch_1" in assessment.contributing_event_ids


def test_legitimate_multi_tool_workflow_not_blocked():
    # Legitimate workflow: Search for concept, then calculate something related
    sid = "benign_chain"
    prior_events = [
        BehavioralEvent(
            event_id="search_1",
            session_id=sid,
            timestamp="2026-10-20T10:00:00Z",
            event_type=BehavioralEventType.TOOL_EXECUTED,
            tool_name="web_search",
            data_sensitivity=DataSensitivity.PUBLIC,
            execution_outcome="success",
        )
    ]

    assessment = assess_behavior(
        tool_name="calculator",
        arguments={"expression": "50 * 2"},
        user_intent=UserIntent.GENERAL_INFORMATION,
        session_events=prior_events,
    )

    # General info allows harmless tools, so score remains low
    assert assessment.risk_score <= 25
    assert assessment.decision == Decision.ALLOW.value


# ============================================================================
# 4. Security Invariant Tests
# ============================================================================

def test_phase3_block_cannot_be_overridden_by_low_behavioral_score():
    # Unknown tool triggers Phase 3 BLOCK; behavioral engine should not override it
    sid = "invariant_block"
    result = execute_tool(
        "unregistered_tool",
        {"param": "val"},
        session_id=sid,
        user_intent=UserIntent.CALCULATION,
    )
    assert result.status == ToolExecutionStatus.BLOCKED
    assert result.decision == Decision.BLOCK


def test_phase3_confirm_cannot_be_downgraded_to_allow():
    # send_email requires CONFIRM in Phase 3; even if behavioral risk were 0, final decision remains CONFIRM
    sid = "invariant_confirm"
    result = execute_tool(
        "send_email",
        {"recipient": "colleague@example.com", "message": "Project update"},
        session_id=sid,
        user_intent=UserIntent.COMMUNICATION,
    )
    assert result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert result.decision == Decision.CONFIRM
    assert result.result is None  # Tool must NOT execute


def test_behavioral_escalation_confirms_out_of_scope_sensitive_read():
    # User intent is CALCULATION. Agent attempts to read confidential file.
    # ACTION_OUTSIDE_REQUEST_SCOPE (25) + SENSITIVE_RESOURCE_WITHOUT_JUSTIFICATION (35) = 60 (CONFIRM)
    sid = "escalation_confirm"
    result = execute_tool(
        "file_read",
        {"filename": "confidential.txt"},
        session_id=sid,
        user_intent=UserIntent.CALCULATION,
    )
    assert result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert result.decision == Decision.CONFIRM
    assert result.risk >= 60
    assert result.result is None  # Never executes without confirmation


def test_behavioral_escalation_blocks_multi_anomaly_scope():
    # Prior event: calculator executed.
    # Current action: out-of-scope confidential file read.
    # Triggers: ACTION_OUTSIDE_REQUEST_SCOPE (25) + SENSITIVE_RESOURCE (35) + UNUSUAL_TOOL_CHAIN (20) = 80 (BLOCK)!
    sid = "escalation_block"
    session_history.add_event(
        BehavioralEvent(
            event_id="prior_calc",
            session_id=sid,
            timestamp="2026-10-20T10:00:00Z",
            event_type=BehavioralEventType.TOOL_EXECUTED,
            tool_name="calculator",
            data_sensitivity=DataSensitivity.PUBLIC,
            execution_outcome="success",
        )
    )
    result = execute_tool(
        "file_read",
        {"filename": "confidential.txt"},
        session_id=sid,
        user_intent=UserIntent.CALCULATION,
    )
    assert result.status == ToolExecutionStatus.BLOCKED
    assert result.decision == Decision.BLOCK
    assert result.risk >= 76
    assert result.result is None  # Absolutely blocked from executing
