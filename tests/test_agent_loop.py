import json
import pytest
from app.agent.agent import run_agent_loop
from app.firewall.audit import clear_audit_events
from app.firewall.session_history import session_history
from app.models.schemas import Decision, SecurityContext


@pytest.fixture(autouse=True)
def clean_session_and_audit():
    clear_audit_events()
    session_history.clear_all()
    yield
    clear_audit_events()
    session_history.clear_all()


def test_agent_loop_valid_tool_call_and_final_answer():
    """Agent requests calculator tool, receives untrusted result, then emits final answer."""
    responses = [
        # Iteration 1: Model requests tool call
        json.dumps({
            "action": "tool_call",
            "tool": "calculator",
            "arguments": {"expression": "12 * 8"}
        }),
        # Iteration 2: Model reads tool result and gives final answer
        json.dumps({
            "action": "final_answer",
            "response": "The result of 12 * 8 is 96."
        })
    ]
    call_idx = 0

    def mock_llm(messages):
        nonlocal call_idx
        resp = responses[call_idx]
        call_idx += 1
        return resp

    result = run_agent_loop(
        user_input="Calculate 12 * 8",
        llm_callable=mock_llm,
        max_iterations=5,
        max_tool_calls=5,
    )

    assert result["status"] == "success"
    assert "96" in result["response"]
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["tool"] == "calculator"
    assert result["tool_calls"][0]["status"] == "success"


def test_agent_loop_unknown_tool_rejected():
    """Model requests an unapproved or arbitrary tool."""
    def mock_llm(messages):
        return json.dumps({
            "action": "tool_call",
            "tool": "shell_execute",
            "arguments": {"cmd": "rm -rf /"}
        })

    result = run_agent_loop(
        user_input="Run a shell command",
        llm_callable=mock_llm,
    )

    assert result["status"] == "blocked"
    assert result["decision"] == Decision.BLOCK.value
    assert "blocked by security policy" in result["response"]
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["status"] == "blocked"


def test_agent_loop_malformed_json_fallback():
    """Model returns non-JSON text; should be treated safely as a direct response."""
    def mock_llm(messages):
        return "I am unable to answer that without more context."

    result = run_agent_loop(
        user_input="Hello",
        llm_callable=mock_llm,
    )

    assert result["status"] == "success"
    assert result["response"] == "I am unable to answer that without more context."
    assert len(result["tool_calls"]) == 0


def test_agent_loop_iteration_limit():
    """Model loops continuously requesting calculator; iteration limit halts execution."""
    def mock_llm(messages):
        return json.dumps({
            "action": "tool_call",
            "tool": "calculator",
            "arguments": {"expression": "1 + 1"}
        })

    result = run_agent_loop(
        user_input="Loop forever",
        llm_callable=mock_llm,
        max_iterations=3,
        max_tool_calls=10,
    )

    assert result["status"] == "limit_exceeded"
    assert "Maximum agent iterations" in result["response"]
    assert len(result["tool_calls"]) == 3


def test_agent_loop_tool_call_limit():
    """Tool call limit is reached before max iterations."""
    def mock_llm(messages):
        return json.dumps({
            "action": "tool_call",
            "tool": "calculator",
            "arguments": {"expression": "2 + 2"}
        })

    result = run_agent_loop(
        user_input="Run multiple tools",
        llm_callable=mock_llm,
        max_iterations=10,
        max_tool_calls=2,
    )

    assert result["status"] == "limit_exceeded"
    assert "Maximum permitted tool calls (2) exceeded" in result["response"]
    assert len(result["tool_calls"]) == 2


def test_agent_loop_confirmation_required_halts():
    """When a tool requires confirmation (e.g. send_email), the agent halts without executing."""
    def mock_llm(messages):
        return json.dumps({
            "action": "tool_call",
            "tool": "send_email",
            "arguments": {"recipient": "ceo@example.com", "message": "Urgent"}
        })

    result = run_agent_loop(
        user_input="Send an email to the CEO",
        llm_callable=mock_llm,
    )

    assert result["status"] == "confirmation_required"
    assert result["decision"] == Decision.CONFIRM.value
    assert "requires explicit confirmation" in result["response"]
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["status"] == "confirmation_required"


def test_agent_loop_untrusted_tool_result_framing():
    """Verify that tool results are explicitly framed as untrusted data in messages."""
    recorded_messages = []

    def mock_llm(messages):
        recorded_messages.extend(messages)
        if len(messages) == 2:
            return json.dumps({
                "action": "tool_call",
                "tool": "web_search",
                "arguments": {"query": "python"}
            })
        return json.dumps({"action": "final_answer", "response": "Python is great."})

    result = run_agent_loop(
        user_input="Tell me about python",
        llm_callable=mock_llm,
    )

    assert result["status"] == "success"
    # Inspect messages fed to LLM in second iteration
    tool_feedback = [m for m in recorded_messages if "[Untrusted Tool Result" in m.get("content", "")]
    assert len(tool_feedback) >= 1
    assert "web_search" in tool_feedback[0]["content"]
