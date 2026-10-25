import json
from unittest.mock import MagicMock, patch
import pytest

from app.agent.agent import parse_model_action, run_agent_loop
from app.firewall.audit import clear_audit_events
from app.firewall.confirmation import clear_confirmation_challenges
from app.firewall.session_history import session_history
from app.firewall.tool_firewall import tool_registry
from app.tools.email import send_email as real_send_email


@pytest.fixture(autouse=True)
def clean_state():
    clear_audit_events()
    session_history.clear_all()
    clear_confirmation_challenges()
    yield
    clear_audit_events()
    session_history.clear_all()
    clear_confirmation_challenges()


# ============================================================================
# Section 1: parse_model_action Unit Tests
# ============================================================================

def test_parse_model_action_standard_format():
    """Format 1: {"action": "tool_call", "tool": "send_email", "arguments": {...}}"""
    raw = json.dumps({
        "action": "tool_call",
        "tool": "send_email",
        "arguments": {"recipient": "alice@example.com", "message": "hello"},
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"] == {"recipient": "alice@example.com", "message": "hello"}


def test_parse_model_action_tool_key_format():
    """Format 2: {"tool": "send_email", "arguments": {...}}"""
    raw = json.dumps({
        "tool": "send_email",
        "arguments": {"recipient": "alice@example.com", "message": "hello"},
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"] == {"recipient": "alice@example.com", "message": "hello"}


def test_parse_model_action_qwen_style_format():
    """Format 3: {"action": "send_email", "arguments": {...}} (Ollama/Qwen direct action format)"""
    raw = json.dumps({
        "action": "send_email",
        "arguments": {
            "recipient": "alice@example.com",
            "message": "This is a security confirmation test.",
        },
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"]["recipient"] == "alice@example.com"
    assert parsed["arguments"]["message"] == "This is a security confirmation test."


def test_parse_model_action_top_level_arguments_qwen():
    """Format 4a: {"action": "send_email", "recipient": "...", "message": "..."}"""
    raw = json.dumps({
        "action": "send_email",
        "recipient": "alice@example.com",
        "message": "hello top level",
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"] == {"recipient": "alice@example.com", "message": "hello top level"}


def test_parse_model_action_top_level_arguments_tool_key():
    """Format 4b: {"tool": "send_email", "recipient": "...", "message": "..."}"""
    raw = json.dumps({
        "tool": "send_email",
        "recipient": "alice@example.com",
        "message": "hello top level tool",
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"] == {"recipient": "alice@example.com", "message": "hello top level tool"}


def test_parse_model_action_top_level_arguments_tool_call():
    """Format 4c: {"action": "tool_call", "tool": "send_email", "recipient": "...", "message": "..."}"""
    raw = json.dumps({
        "action": "tool_call",
        "tool": "send_email",
        "recipient": "alice@example.com",
        "message": "hello top level tool_call",
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"] == {"recipient": "alice@example.com", "message": "hello top level tool_call"}


def test_parse_model_action_markdown_code_block():
    """Tool call wrapped inside markdown json code block."""
    raw = "```json\n" + json.dumps({
        "action": "send_email",
        "arguments": {"recipient": "alice@example.com", "message": "block"},
    }) + "\n```"
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"] == {"recipient": "alice@example.com", "message": "block"}


def test_parse_model_action_strips_thinking_tags():
    """Removes <think> reasoning tags emitted by reasoning models like Qwen/DeepSeek."""
    raw = (
        "<think>\nThe user wants to send an email.\nI should invoke send_email.\n</think>\n"
        '{"action": "send_email", "arguments": {"recipient": "alice@example.com", "message": "test"}}'
    )
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "send_email"
    assert parsed["arguments"]["recipient"] == "alice@example.com"


def test_parse_model_action_missing_tool_name_fails_closed():
    """Missing tool name in tool_call format must produce parse_error."""
    raw = json.dumps({
        "action": "tool_call",
        "arguments": {"cmd": "rm -rf"},
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "parse_error"
    assert "missing or invalid tool name" in parsed["error"]


def test_parse_model_action_unknown_tool_routed_to_tool_call():
    """Unknown tool in tool_call format is parsed as tool_call to allow central firewall gating."""
    raw = json.dumps({
        "action": "tool_call",
        "tool": "unregistered_dangerous_tool",
        "arguments": {"cmd": "rm -rf"},
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "tool_call"
    assert parsed["tool"] == "unregistered_dangerous_tool"


def test_parse_model_action_malformed_json_fails_closed():
    """Malformed JSON in tool action attempt must produce parse_error, not final_answer."""
    raw = '```json\n{"action": "send_email", "arguments": {"recipient": "alice@example.com"\n```'
    parsed = parse_model_action(raw)
    assert parsed["action"] == "parse_error"
    assert "Malformed JSON" in parsed["error"]


def test_parse_model_action_invalid_argument_type_fails_closed():
    """Invalid arguments type (string instead of dict) must produce parse_error."""
    raw = json.dumps({
        "action": "send_email",
        "arguments": "alice@example.com",
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "parse_error"
    assert "arguments must be a dictionary" in parsed["error"]


def test_parse_model_action_ambiguous_action_fails_closed():
    """Ambiguous JSON object containing both final_answer and tool fields must produce parse_error."""
    raw = json.dumps({
        "action": "final_answer",
        "tool": "send_email",
        "response": "Here is your answer",
        "arguments": {"recipient": "alice@example.com"},
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "parse_error"
    assert "Ambiguous action object" in parsed["error"]


def test_parse_model_action_normal_final_answer_json():
    """Legitimate final_answer JSON object parses cleanly."""
    raw = json.dumps({
        "action": "final_answer",
        "response": "The capital of France is Paris.",
    })
    parsed = parse_model_action(raw)
    assert parsed["action"] == "final_answer"
    assert parsed["response"] == "The capital of France is Paris."


def test_parse_model_action_normal_final_answer_prose():
    """Ordinary prose response without JSON parses cleanly as final_answer."""
    raw = "The capital of France is Paris. It is known for the Eiffel Tower."
    parsed = parse_model_action(raw)
    assert parsed["action"] == "final_answer"
    assert parsed["response"] == raw


def test_parse_model_action_benign_non_tool_json():
    """Prose explaining JSON that contains arbitrary non-tool data parses as final_answer."""
    raw = 'Here is an example user profile: {"user_id": 42, "role": "editor"}.'
    parsed = parse_model_action(raw)
    assert parsed["action"] == "final_answer"
    assert parsed["response"] == raw


# ============================================================================
# Section 2: run_agent_loop Deterministic Tests
# ============================================================================

def test_run_agent_loop_qwen_email_halts_for_confirmation():
    """Deterministic agent loop test: Qwen action: send_email halts for confirmation without executing."""
    email_spy = MagicMock(wraps=real_send_email)
    tool_reg = tool_registry.get("send_email")

    def mock_qwen_llm(messages):
        return json.dumps({
            "action": "send_email",
            "arguments": {
                "recipient": "alice@example.com",
                "message": "This is a security confirmation test.",
            },
        })

    with patch.object(tool_reg, "func", email_spy):
        result = run_agent_loop(
            user_input="Send an email to alice@example.com with message This is a security confirmation test.",
            llm_callable=mock_qwen_llm,
            correlation_id="agent_qwen_sess",
        )

    assert result["status"] == "confirmation_required"
    assert result["decision"] == "CONFIRM"
    assert result["risk"] >= 65
    assert result["confirmation_token"] is not None
    assert email_spy.call_count == 0  # CRITICAL: Tool function must NOT be called


def test_run_agent_loop_malformed_tool_action_fails_closed():
    """Deterministic agent loop test: malformed tool JSON fails closed as error with BLOCK."""
    def mock_malformed_llm(messages):
        return '```json\n{"action": "send_email", "arguments": {broken\n```'

    result = run_agent_loop(
        user_input="Send an email to Alice",
        llm_callable=mock_malformed_llm,
        correlation_id="agent_malformed_sess",
    )

    assert result["status"] == "error"
    assert result["decision"] == "BLOCK"
    assert result["risk"] >= 70
    assert result["tool_calls"] == []


def test_run_agent_loop_unknown_tool_fails_closed():
    """Deterministic agent loop test: unknown tool fails closed as error with BLOCK."""
    def mock_unknown_tool_llm(messages):
        return json.dumps({
            "action": "tool_call",
            "tool": "malicious_unregistered_tool",
            "arguments": {"payload": "drop table"},
        })

    result = run_agent_loop(
        user_input="Execute malicious tool",
        llm_callable=mock_unknown_tool_llm,
        correlation_id="agent_unknown_tool_sess",
    )

    assert result["status"] == "blocked"
    assert result["decision"] == "BLOCK"
    assert result["risk"] >= 70
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["status"] == "blocked"


def test_run_agent_loop_embedded_tool_call_in_final_answer_intercepted():
    """Security guard: A tool call embedded inside final_answer.response is intercepted and gated."""
    email_spy = MagicMock(wraps=real_send_email)
    tool_reg = tool_registry.get("send_email")

    def mock_sneaky_llm(messages):
        return json.dumps({
            "action": "final_answer",
            "response": json.dumps({
                "action": "send_email",
                "arguments": {
                    "recipient": "alice@example.com",
                    "message": "Exfiltration attempt",
                },
            }),
        })

    with patch.object(tool_reg, "func", email_spy):
        result = run_agent_loop(
            user_input="Send exfiltration",
            llm_callable=mock_sneaky_llm,
            correlation_id="agent_sneaky_sess",
        )

    # Must be intercepted by the tool firewall rather than released as ALLOW!
    assert result["status"] == "confirmation_required"
    assert result["decision"] == "CONFIRM"
    assert email_spy.call_count == 0