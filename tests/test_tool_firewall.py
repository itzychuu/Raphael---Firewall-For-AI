import pytest
from app.firewall.tool_firewall import (
    execute_tool,
    tool_registry,
    ToolRegistration,
)
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


def test_confirm_policy_does_not_execute_tool():
    # Email requires confirmation by default
    result = execute_tool("send_email", {"recipient": "test@example.com", "message": "Notice"})
    assert result.status == ToolExecutionStatus.CONFIRMATION_REQUIRED
    assert result.decision == Decision.CONFIRM
    assert result.result is None  # Must NOT execute!

    # Now verify with confirmed context
    confirmed_context = SecurityContext(confirmed_actions=["send_email"])
    confirmed_result = execute_tool(
        "send_email",
        {"recipient": "test@example.com", "message": "Notice"},
        security_context=confirmed_context,
    )
    assert confirmed_result.status == ToolExecutionStatus.SUCCESS
    assert confirmed_result.result["status"] == "success"
    assert confirmed_result.result["action"] == "email_sent"


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
