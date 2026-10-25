import pytest
from app.firewall.tool_firewall import (
    execute_tool,
    tool_registry,
    ToolRegistration,
)
from app.firewall.confirmation import canonical_action_id
from app.firewall.audit import get_audit_events, clear_audit_events
from app.models.schemas import (
    Decision,
    SecurityContext,
    ToolExecutionStatus,
    CalculatorArgs,
)


from app.firewall.session_history import session_history


@pytest.fixture(autouse=True)
def clean_audit_log():
    clear_audit_events()
    session_history.clear_all()
    yield
    clear_audit_events()
    session_history.clear_all()


def test_registered_tool_valid_execution():
    context = SecurityContext()
    result = execute_tool("calculator", {"expression": "25 * 40"}, security_context=context)

    assert result.status == ToolExecutionStatus.SUCCESS
    assert result.decision == Decision.ALLOW
    assert result.result["status"] == "success"
    assert result.result["result"] == 1000

    # Check audit log
    events = get_audit_events()
    assert any(e.tool_name == "calculator" and e.outcome == "success" for e in events)


def test_registered_web_search():
    result = execute_tool("web_search", {"query": "python"})
    assert result.status == ToolExecutionStatus.SUCCESS
    assert result.result["status"] == "success"
    assert "Python is a high-level" in result.result["result"]


def test_registered_database_read_monitored():
    result = execute_tool("database_read", {"employee_id": "employee_001"})
    assert result.status == ToolExecutionStatus.SUCCESS
    assert result.decision == Decision.MONITOR
    assert result.result["status"] == "success"
    assert result.result["data"]["name"] == "Alice"


def test_unknown_tool_rejected():
    result = execute_tool("arbitrary_exec", {"command": "dir"})
    assert result.status == ToolExecutionStatus.BLOCKED
    assert result.decision == Decision.BLOCK
    assert "not permitted or does not exist" in result.error

    events = get_audit_events()
    assert any(e.outcome == "rejected_unknown_tool" for e in events)


def test_missing_arguments_rejected():
    result = execute_tool("calculator", {})
    assert result.status == ToolExecutionStatus.VALIDATION_ERROR
    assert result.decision == Decision.BLOCK
    assert "validation failed" in result.error.lower()


def test_unexpected_arguments_rejected():
    result = execute_tool("calculator", {"expression": "10 + 20", "malicious_extra": "drop table"})
    assert result.status == ToolExecutionStatus.VALIDATION_ERROR
    assert result.decision == Decision.BLOCK
    assert "validation failed" in result.error.lower()


def test_invalid_argument_types_rejected():
    # Expression must be a string, not a dictionary or list
    result = execute_tool("calculator", {"expression": ["10", "+", "20"]})
    assert result.status == ToolExecutionStatus.VALIDATION_ERROR
    assert result.decision == Decision.BLOCK


def test_unauthorized_operation_rejected():
    # User lacks permission for database
    restricted_context = SecurityContext(permissions=["tools:calculate"])
    result = execute_tool(
        "database_read",
        {"employee_id": "employee_001"},
        security_context=restricted_context,
    )
    assert result.status == ToolExecutionStatus.UNAUTHORIZED
    assert result.decision == Decision.BLOCK
    assert "Permission denied" in result.error



# ============================================================================
# Section A: Unit-Level Tool-Firewall Tests (Confirmation Authorization)
# ============================================================================

def test_email_without_confirmation_requires_confirm_and_does_not_execute():
    """A.1: Email without confirmation returns CONFIRMATION_REQUIRED and does not execute."""
    args = {"recipient": "alice@example.com", "message": "Important notice"}
    result = execute_tool("send_email", args)
    assert result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert result.decision == Decision.CONFIRM
    assert result.result is None  # Must NOT execute!


def test_authorization_for_alice_cannot_authorize_bob():
    """A.2: An authorization for Alice cannot authorize Bob."""
    alice_args = {"recipient": "alice@example.com", "message": "Notice"}
    bob_args = {"recipient": "bob@example.com", "message": "Notice"}

    alice_action = canonical_action_id("send_email", alice_args)
    alice_context = SecurityContext(confirmed_actions=[alice_action])

    bob_result = execute_tool("send_email", bob_args, security_context=alice_context)
    assert bob_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert bob_result.decision == Decision.CONFIRM
    assert bob_result.result is None


def test_authorization_for_one_message_cannot_authorize_different_message():
    """A.3: An authorization for one message cannot authorize a different message."""
    orig_args = {"recipient": "alice@example.com", "message": "Approved message"}
    tampered_args = {"recipient": "alice@example.com", "message": "Tampered malicious payload"}

    orig_action = canonical_action_id("send_email", orig_args)
    approved_context = SecurityContext(confirmed_actions=[orig_action])

    tampered_result = execute_tool("send_email", tampered_args, security_context=approved_context)
    assert tampered_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert tampered_result.decision == Decision.CONFIRM
    assert tampered_result.result is None


def test_exact_matching_authorization_permits_approved_action():
    """A.4: An exact matching authorization permits only the approved action."""
    args = {"recipient": "alice@example.com", "message": "Safe notice"}
    approved_action = canonical_action_id("send_email", args)
    context = SecurityContext(confirmed_actions=[approved_action])

    result = execute_tool("send_email", args, security_context=context)
    assert result.status == ToolExecutionStatus.SUCCESS
    assert result.decision in (Decision.ALLOW, Decision.MONITOR)
    assert result.result is not None
    assert result.result["status"] == "success"
    assert result.result["simulated"] is True
    assert result.result["recipient"] == "alice@example.com"


def test_generic_send_email_authorization_cannot_bypass_scoped_confirmation():
    """A.5: Generic send_email or recipient-only authorization cannot bypass exact confirmation requirement."""
    args = {"recipient": "alice@example.com", "message": "Notice"}

    # Generic "send_email" attempt
    generic_context = SecurityContext(confirmed_actions=["send_email"])
    gen_result = execute_tool("send_email", args, security_context=generic_context)
    assert gen_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert gen_result.result is None

    # Recipient-only "send_email:alice@example.com" without message hash attempt
    recipient_only_context = SecurityContext(confirmed_actions=["send_email:alice@example.com"])
    rec_result = execute_tool("send_email", args, security_context=recipient_only_context)
    assert rec_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert rec_result.result is None


def test_client_supplied_confirmation_strings_cannot_grant_authorization():
    """A.6: Client-supplied wildcard or invalid confirmation strings cannot grant authorization."""
    args = {"recipient": "alice@example.com", "message": "Notice"}

    for invalid_action in ["*", "send_email:*", "send_email:alice@example.com:*", "all_tools"]:
        context = SecurityContext(confirmed_actions=[invalid_action])
        result = execute_tool("send_email", args, security_context=context)
        assert result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
        assert result.result is None




def test_authorization_for_one_subject_cannot_authorize_different_subject():
    """A.7: An authorization for one subject cannot authorize a different subject."""
    orig_args = {"recipient": "alice@example.com", "message": "Notice", "subject": "Quarterly Update"}
    tampered_args = {"recipient": "alice@example.com", "message": "Notice", "subject": "Urgent Wire Transfer"}

    orig_action = canonical_action_id("send_email", orig_args)
    approved_context = SecurityContext(confirmed_actions=[orig_action])

    tampered_result = execute_tool("send_email", tampered_args, security_context=approved_context)
    assert tampered_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert tampered_result.decision == Decision.CONFIRM
    assert tampered_result.result is None


def test_filename_only_file_read_authorization_cannot_bypass_canonical_confirmation():
    """A.8: Filename-only or generic file_read authorization cannot bypass canonical confirmation."""
    args = {"filename": "confidential.txt"}

    # Legacy filename-only "file_read:confidential.txt" must be rejected
    filename_only_ctx = SecurityContext(confirmed_actions=["file_read:confidential.txt"])
    fn_result = execute_tool("file_read", args, security_context=filename_only_ctx)
    assert fn_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert fn_result.result is None

    # Generic "file_read" must be rejected
    generic_ctx = SecurityContext(confirmed_actions=["file_read"])
    gen_result = execute_tool("file_read", args, security_context=generic_ctx)
    assert gen_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert gen_result.result is None

    # Wildcard "file_read:*" must be rejected
    wildcard_ctx = SecurityContext(confirmed_actions=["file_read:*"])
    wc_result = execute_tool("file_read", args, security_context=wildcard_ctx)
    assert wc_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert wc_result.result is None

    # Exact matching canonical action ID must succeed
    canonical_action = canonical_action_id("file_read", args)
    exact_ctx = SecurityContext(confirmed_actions=[canonical_action])
    exact_result = execute_tool("file_read", args, security_context=exact_ctx)
    assert exact_result.status == ToolExecutionStatus.SUCCESS
    assert exact_result.result is not None


def test_confidential_file_requires_confirmation():
    # Normal file is allowed
    normal_result = execute_tool("file_read", {"filename": "public_report.txt"})
    assert normal_result.status == ToolExecutionStatus.SUCCESS

    # Confidential file requires confirmation
    confidential_result = execute_tool("file_read", {"filename": "confidential.txt"})
    assert confidential_result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert confidential_result.decision == Decision.CONFIRM
    assert confidential_result.result is None  # Must NOT leak content!


def test_path_traversal_strictly_rejected():
    traversal_inputs = [
        "../../secret.txt",
        "..\\windows\\system32.txt",
        "/etc/passwd.txt",
        "nested/report.txt",
        "file\x00.txt",
    ]
    for bad_path in traversal_inputs:
        result = execute_tool("file_read", {"filename": bad_path})
        assert result.status == ToolExecutionStatus.VALIDATION_ERROR
        assert result.decision == Decision.BLOCK
        assert result.result is None


def test_calculator_code_execution_blocked():
    malicious_expressions = [
        "__import__('os').system('dir')",
        "eval('2+2')",
        "open('/etc/passwd').read()",
        "import sys",
        "10 + abc",
    ]
    for expr in malicious_expressions:
        result = execute_tool("calculator", {"expression": expr})
        assert result.status == ToolExecutionStatus.VALIDATION_ERROR
        assert result.decision == Decision.BLOCK
        assert result.result is None


def test_tool_exceptions_handled_safely():
    # Register a faulty tool that crashes
    def faulty_tool(expression: str):
        raise RuntimeError("Low-level database connection crash: password=secret123")

    faulty_reg = ToolRegistration(
        name="faulty_calc",
        func=faulty_tool,
        schema=CalculatorArgs,
        required_permission="tools:calculate",
        default_risk=10,
        default_decision=Decision.ALLOW,
        description="Faulty test tool",
    )
    tool_registry.register(faulty_reg)

    result = execute_tool("faulty_calc", {"expression": "1 + 1"})
    assert result.status == ToolExecutionStatus.EXECUTION_ERROR
    # Verify sensitive crash message is NOT leaked to caller
    assert "password" not in (result.error or "")
    assert "secret123" not in (result.error or "")
    assert "Tool execution encountered an internal error" in result.error
