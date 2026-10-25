import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.agent.agent import run_agent_loop
from app.firewall.audit import clear_audit_events, get_audit_events
from app.firewall.data_provenance import create_tool_provenance, elevate_provenance
from app.firewall.dlp_detector import scan_text_for_dlp
from app.firewall.output_firewall import inspect_output
from app.firewall.redaction import merge_overlapping_findings, redact_text
import concurrent.futures
from app.firewall.confirmation import (
    canonical_action_id,
    clear_confirmation_challenges,
    create_confirmation_challenge,
    validate_and_consume_challenge,
)
from app.firewall.session_history import session_history
from app.main import app
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

client = TestClient(app)


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
# 1. DLP Detection Tests
# ============================================================================

def test_dlp_benign_text():
    text = "The quick brown fox jumps over the lazy dog. Math result: 25 * 40 = 1000."
    findings = scan_text_for_dlp(text)
    # No credentials, SSNs, or secrets
    assert len([f for f in findings if f.category != DLPFindingCategory.EMAIL_ADDRESS]) == 0


def test_dlp_detects_synthetic_ssn():
    text = "Employee Alice record: SSN is 999-12-3456 and Bob SSN is 888-23-4567."
    findings = scan_text_for_dlp(text)
    ssn_findings = [f for f in findings if f.category == DLPFindingCategory.SSN]
    assert len(ssn_findings) == 2
    assert all(f.sensitivity == "restricted" for f in ssn_findings)


def test_dlp_detects_api_keys():
    text = "Use project secret CONFIDENTIAL: Project API key = TEST-API-KEY-12345 to authenticate."
    findings = scan_text_for_dlp(text)
    api_key_findings = [f for f in findings if f.category == DLPFindingCategory.API_KEY]
    assert len(api_key_findings) >= 1
    assert api_key_findings[0].sensitivity == "restricted"


def test_dlp_detects_password_assignment():
    text = "Database connection string: user=admin; password=SuperSecretPassword123!; host=localhost"
    findings = scan_text_for_dlp(text)
    pwd_findings = [f for f in findings if f.category == DLPFindingCategory.PASSWORD]
    assert len(pwd_findings) == 1
    assert pwd_findings[0].sensitivity == "restricted"


def test_dlp_detects_multiline_private_key():
    pem_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1+synthetic+mock+private+key+payload+for+testing\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"Here is the server configuration:\n{pem_key}\nSave this safely."
    findings = scan_text_for_dlp(text)
    key_findings = [f for f in findings if f.category == DLPFindingCategory.PRIVATE_KEY]
    assert len(key_findings) == 1
    assert key_findings[0].sensitivity == "restricted"


def test_dlp_multiple_sensitive_categories():
    text = (
        "Confidential leak: SSN=999-12-3456, key=TEST-API-KEY-SECRET999, "
        "password=SecretPass123, email=admin@company.com"
    )
    findings = scan_text_for_dlp(text)
    categories = {f.category for f in findings}
    assert DLPFindingCategory.SSN in categories
    assert DLPFindingCategory.API_KEY in categories
    assert DLPFindingCategory.PASSWORD in categories
    assert DLPFindingCategory.EMAIL_ADDRESS in categories


# ============================================================================
# 2. Redaction Engine Tests
# ============================================================================

def test_redact_ssn_and_api_key():
    text = "Alice SSN is 999-12-3456 and token is TEST-API-KEY-12345."
    findings = scan_text_for_dlp(text)
    redacted = redact_text(text, findings)

    assert "[REDACTED_SSN]" in redacted
    assert "[REDACTED_API_KEY]" in redacted
    assert "999-12-3456" not in redacted
    assert "TEST-API-KEY-12345" not in redacted


def test_redact_multiline_private_key():
    pem_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n"
        "-----END PRIVATE KEY-----"
    )
    text = f"Certificate:\n{pem_key}\nEnd of cert."
    findings = scan_text_for_dlp(text)
    redacted = redact_text(text, findings)

    assert "[REDACTED_PRIVATE_KEY]" in redacted
    assert "-----BEGIN PRIVATE KEY-----" not in redacted


def test_redact_overlapping_findings():
    # Construct synthetic overlapping findings
    f1 = DLPFinding(
        category=DLPFindingCategory.API_KEY,
        start=10,
        end=25,
        matched_text_length=15,
        sensitivity="restricted",
        description="Key span",
    )
    f2 = DLPFinding(
        category=DLPFindingCategory.PASSWORD,
        start=15,
        end=30,
        matched_text_length=15,
        sensitivity="restricted",
        description="Overlapping span",
    )
    merged = merge_overlapping_findings([f1, f2])
    assert len(merged) == 1
    assert merged[0].start == 10
    assert merged[0].end == 30


def test_redaction_idempotence():
    text = "SSN 999-12-3456 and key TEST-API-KEY-12345"
    findings_1 = scan_text_for_dlp(text)
    pass_1 = redact_text(text, findings_1)

    # Second pass on already redacted string
    findings_2 = scan_text_for_dlp(pass_1)
    pass_2 = redact_text(pass_1, findings_2)

    assert pass_1 == pass_2


# ============================================================================
# 3. Data Provenance Tests
# ============================================================================

def test_provenance_creation():
    prov_public = create_tool_provenance("file_read", {"filename": "public_report.txt"})
    assert prov_public.sensitivity == "public"

    prov_confidential = create_tool_provenance("file_read", {"filename": "confidential.txt"})
    assert prov_confidential.sensitivity == "confidential"
    assert prov_confidential.required_permission == "disclose:confidential"

    prov_db = create_tool_provenance("database_read", {"employee_id": "employee_001"})
    assert prov_db.sensitivity == "confidential"


def test_provenance_elevation_preserves_highest_sensitivity():
    p1 = create_tool_provenance("web_search", {"query": "python"})  # PUBLIC
    p2 = create_tool_provenance("calculator", {"expression": "2+2"})  # PUBLIC
    p3 = create_tool_provenance("file_read", {"filename": "confidential.txt"})  # CONFIDENTIAL

    combined = elevate_provenance([p1, p2, p3])
    # Must preserve the highest sensitivity (confidential), cannot downgrade
    assert combined.sensitivity == "confidential"
    assert combined.required_permission == "disclose:confidential"


# ============================================================================
# 4. Authorization & Disclosure Policy Tests
# ============================================================================

def test_inspect_output_public_allowed():
    text = "Python is a high-level programming language."
    result = inspect_output(text, destination="api_client")
    assert result.decision == OutputDecision.ALLOW
    assert result.release_permitted is True


def test_inspect_output_restricted_redacted_for_ordinary_client():
    text = "The employee SSN is 999-12-3456 and salary is $75000."
    context = SecurityContext()  # Ordinary user lacking disclose:restricted
    result = inspect_output(text, security_context=context, destination="api_client")

    assert result.decision == OutputDecision.REDACT
    assert result.release_permitted is True
    assert "[REDACTED_SSN]" in result.redacted_content
    assert "999-12-3456" not in result.redacted_content


def test_inspect_output_restricted_allowed_with_explicit_permission():
    text = "Employee SSN is 999-12-3456."
    privileged_context = SecurityContext(permissions=["disclose:restricted", "disclose:confidential"])
    result = inspect_output(text, security_context=privileged_context, destination="api_client")
    assert result.decision == OutputDecision.ALLOW
    assert result.release_permitted is True


def test_inspect_output_fail_closed_on_error():
    # Pass an un-serializable object that triggers exception handling in scan
    with patch("app.firewall.output_firewall.scan_data_for_dlp", side_effect=RuntimeError("Scanner crash")):
        result = inspect_output("Normal text", destination="api_client")
        assert result.decision == OutputDecision.BLOCK
        assert result.release_permitted is False
        assert "fail-closed" in result.explanation


# ============================================================================
# 5. Agent Loop & API Integration Tests
# ============================================================================

def test_agent_tool_result_masked_before_llm_context():
    """Verify raw restricted secrets (like SSNs) in tool results are masked before entering LLM messages."""
    recorded_messages = []

    def mock_llm(messages):
        recorded_messages.extend(messages)
        if len(messages) == 2:
            return json.dumps({
                "action": "tool_call",
                "tool": "database_read",
                "arguments": {"employee_id": "employee_001"}
            })
        return json.dumps({"action": "final_answer", "response": "Found employee record."})

    auth_context = SecurityContext(permissions=["tools:database_read", "disclose:confidential"])
    result = run_agent_loop(
        user_input="Look up employee_001",
        security_context=auth_context,
        llm_callable=mock_llm,
    )

    assert result["status"] == "success"
    # Inspect messages fed to LLM on second turn: SSN must be masked!
    tool_results = [m["content"] for m in recorded_messages if "[Untrusted Tool Result" in m.get("content", "")]
    assert len(tool_results) >= 1
    assert "999-12-3456" not in tool_results[0]
    assert "[REDACTED_SSN]" in tool_results[0]


def test_agent_final_response_redacted_for_client():
    """Verify model output attempting to leak secrets is redacted before client delivery."""
    def mock_llm(messages):
        return json.dumps({
            "action": "final_answer",
            "response": "Here is the confidential key: TEST-API-KEY-12345"
        })

    result = run_agent_loop(
        user_input="Give me the project key",
        llm_callable=mock_llm,
    )

    assert result["status"] == "success"
    assert "TEST-API-KEY-12345" not in result["response"]
    assert "[REDACTED_API_KEY]" in result["response"]


def test_api_inspect_output_endpoint():
    response = client.post(
        "/inspect-output",
        json={"content": "Employee SSN: 999-12-3456, key: TEST-API-KEY-9999", "destination": "api_client"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "REDACT"
    assert data["findings_count"] >= 2
    assert "[REDACTED_SSN]" in data["redacted_content"]
    assert "[REDACTED_API_KEY]" in data["redacted_content"]


# ============================================================================
# 6. Phase 5 Security Remediation & Adversarial Tests
# ============================================================================

def test_read_permission_does_not_authorize_disclosure():
    """Verify that possessing tools:file_read or tools:database_read does NOT authorize disclosure."""
    # Context has read permissions, but lacks disclose:confidential
    reader_context = SecurityContext(permissions=["tools:file_read", "tools:database_read"])
    prov = create_tool_provenance("file_read", {"filename": "confidential.txt"})

    # 1. Output containing explicit findings must be REDACTED, never ALLOWED
    text_with_findings = "The employee salary is $140,000 according to confidential records."
    result = inspect_output(text_with_findings, security_context=reader_context, provenance=prov, destination="api_client")
    assert result.decision == OutputDecision.REDACT
    assert "[REDACTED_CONFIDENTIAL_DATA]" in result.redacted_content

    # 2. Output without exact regex matches must be held for CONFIRMATION, never ALLOWED
    text_narrative = "The file details our merger with Apex Holdings."
    result_narrative = inspect_output(text_narrative, security_context=reader_context, provenance=prov, destination="api_client")
    assert result_narrative.decision == OutputDecision.CONFIRM
    assert result_narrative.release_permitted is False


def test_confidential_provenance_paraphrased_output_requires_confirmation():
    """Verify that paraphrased narrative output deriving from confidential data requires confirmation."""
    prov = create_tool_provenance("file_read", {"filename": "confidential.txt"})
    ordinary_context = SecurityContext(permissions=["tools:file_read"])

    # Paraphrased summary containing zero regex findings
    paraphrased = "The unreleased quarterly revenue strategy aims to expand into European logistics."
    findings = scan_text_for_dlp(paraphrased)
    assert len(findings) == 0  # No regex matches

    result = inspect_output(paraphrased, security_context=ordinary_context, provenance=prov, destination="api_client")
    assert result.decision == OutputDecision.CONFIRM
    assert result.release_permitted is False
    assert "confidential.txt" in result.explanation
    assert result.redacted_content is None


def test_restricted_provenance_without_regex_matches_blocks():
    """Verify that output deriving from restricted source data without identifiable regex spans is blocked."""
    prov = DataProvenance(
        provenance_id="prov_test_restricted",
        source_tool="credentials_vault",
        source_resource="root_key",
        sensitivity="restricted",
        required_permission="disclose:restricted",
    )
    ordinary_context = SecurityContext()

    narrative = "The administrator cryptographic master secret has been verified."
    result = inspect_output(narrative, security_context=ordinary_context, provenance=prov, destination="api_client")
    assert result.decision == OutputDecision.BLOCK
    assert result.release_permitted is False
    assert "cannot be safely redacted" in result.explanation


def test_unrelated_prior_confidential_tool_does_not_block_subsequent_public_response():
    """Verify that a current response deriving solely from public tools is NOT held due to prior session events."""
    # Current response derives ONLY from calculator (public tool)
    calculator_prov = create_tool_provenance("calculator", {"expression": "50*2"})
    ordinary_context = SecurityContext()

    result = inspect_output("100", security_context=ordinary_context, provenance=calculator_prov, destination="api_client")
    assert result.decision == OutputDecision.ALLOW
    assert result.release_permitted is True


def test_inspect_output_api_destination_override_ignored():
    """Verify that public /inspect-output ignores client-supplied destination='agent_context'."""
    # Confidential payload: should be ALLOW in agent_context, but REDACT in api_client
    response = client.post(
        "/inspect-output",
        json={
            "content": "Confidential employee salary is $125000",
            "destination": "agent_context",  # Attacker attempt to force permissive internal mode
        },
    )
    assert response.status_code == 200
    data = response.json()
    # Server must force api_client destination and redact
    assert data["destination"] == "api_client"
    assert data["decision"] == "REDACT"
    assert "[REDACTED_CONFIDENTIAL_DATA]" in data["redacted_content"]


def test_behavior_session_unauthorized_access_rejected(monkeypatch):
    """Verify that /behavior/session/{session_id} fails closed without config and rejects unauthorized calls."""
    # 1. Unconfigured environment -> 503 Service Unavailable (fail closed)
    monkeypatch.delenv("RAPHAEL_RESEARCH_TOKEN", raising=False)
    resp_unconfigured = client.get("/behavior/session/secret_session_999")
    assert resp_unconfigured.status_code == 503
    assert "disabled" in resp_unconfigured.json()["detail"].lower()

    # 2. Configured with secure research token
    monkeypatch.setenv("RAPHAEL_RESEARCH_TOKEN", "secure-research-token-xyz-12345")

    # 2a. Missing auth header -> 403 Forbidden
    resp_no_auth = client.get("/behavior/session/secret_session_999")
    assert resp_no_auth.status_code == 403
    assert "Unauthorized" in resp_no_auth.json()["detail"]

    # 2b. Forged/invalid auth header -> 403 Forbidden
    resp_bad_auth = client.get(
        "/behavior/session/secret_session_999",
        headers={"X-RAPHAEL-RESEARCH-TOKEN": "forged-token-xyz"},
    )
    assert resp_bad_auth.status_code == 403

    # 2c. Valid research header -> 200 OK
    resp_valid = client.get(
        "/behavior/session/secret_session_999",
        headers={"X-RAPHAEL-RESEARCH-TOKEN": "secure-research-token-xyz-12345"},
    )
    assert resp_valid.status_code == 200
    assert resp_valid.json()["session_id"] == "secret_session_999"


def test_forged_and_wildcard_confirmation_rejected():
    """Verify that client-supplied confirmed_actions=['*'] does not grant confirmation."""
    def mock_agent_loop(**kwargs):
        ctx = kwargs.get("security_context")
        # Assert that wildcard was stripped or not present in confirmed_actions
        assert "*" not in ctx.confirmed_actions
        return {
            "status": "confirmation_required",
            "response": "Action 'send_email' requires explicit confirmation.",
            "decision": "CONFIRM",
            "risk": 65,
            "tool_calls": [],
        }

    with patch("app.main.run_agent_loop", side_effect=mock_agent_loop):
        resp = client.post(
            "/chat",
            json={
                "message": "Send email to team",
                "confirmed_actions": ["*"],  # Forged wildcard confirmation attempt
            },
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "CONFIRM"


def test_confirmation_challenge_single_use_prevents_replay():
    """Verify that server-issued confirmation tokens can only be consumed once."""
    token = create_confirmation_challenge(
        action="send_email",
        session_id="sess_100",
        parameters={"recipient": "user@example.com"},
    )

    # First consumption: valid
    assert validate_and_consume_challenge(
        token=token,
        action="send_email",
        session_id="sess_100",
        parameters={"recipient": "user@example.com"},
    ) is True

    # Second consumption: rejected (replay attack prevention)
    assert validate_and_consume_challenge(
        token=token,
        action="send_email",
        session_id="sess_100",
        parameters={"recipient": "user@example.com"},
    ) is False


def test_confirmation_challenge_parameter_mismatch_rejected():
    """Verify that challenge tokens bound to specific parameters reject altered parameters."""
    token = create_confirmation_challenge(
        action="send_email",
        session_id="sess_200",
        parameters={"recipient": "finance@company.com"},
    )

    # Attempt to consume token with altered recipient
    assert validate_and_consume_challenge(
        token=token,
        action="send_email",
        session_id="sess_200",
        parameters={"recipient": "attacker@evil.com"},
    ) is False


def test_confirmation_challenge_expired_token_fails():
    """B.3: Verify that an expired confirmation token fails validation and cannot be consumed."""
    token = create_confirmation_challenge(
        action="send_email",
        session_id="sess_expired",
        parameters={"recipient": "user@example.com"},
        ttl_seconds=-10,  # Immediately expired
    )
    assert validate_and_consume_challenge(
        token=token,
        action="send_email",
        session_id="sess_expired",
        parameters={"recipient": "user@example.com"},
    ) is False


def test_confirmation_challenge_wrong_session_fails():
    """B.4: Verify that a token used with a mismatched session fails."""
    token = create_confirmation_challenge(
        action="send_email",
        session_id="session_legitimate",
        parameters={"recipient": "user@example.com"},
    )
    assert validate_and_consume_challenge(
        token=token,
        action="send_email",
        session_id="session_hijacked",
        parameters={"recipient": "user@example.com"},
    ) is False


def test_confirmation_challenge_wrong_action_fails():
    """B.5: Verify that a token issued for one action fails when redeemed for a different action."""
    token = create_confirmation_challenge(
        action="send_email",
        session_id="sess_action_test",
        parameters={"recipient": "user@example.com"},
    )
    assert validate_and_consume_challenge(
        token=token,
        action="file_read",
        session_id="sess_action_test",
        parameters={"filename": "confidential.txt"},
    ) is False


def test_token_scope_separation_recipient_and_message():
    """B.7: Verify that canonical action IDs for different recipients or messages differ."""
    base_args = {"recipient": "alice@example.com", "message": "Secret message 1"}
    diff_recipient = {"recipient": "bob@example.com", "message": "Secret message 1"}
    diff_message = {"recipient": "alice@example.com", "message": "Secret message 2"}

    id_base = canonical_action_id("send_email", base_args)
    id_diff_recipient = canonical_action_id("send_email", diff_recipient)
    id_diff_message = canonical_action_id("send_email", diff_message)

    assert id_base != id_diff_recipient
    assert id_base != id_diff_message
    assert id_diff_recipient != id_diff_message
    assert id_base.startswith("send_email:alice@example.com:")
    assert id_diff_recipient.startswith("send_email:bob@example.com:")


def test_cross_challenge_type_isolation():
    """B.8: Verify that a disclosure challenge cannot authorize a tool action, and vice versa."""
    tok_disclose = create_confirmation_challenge(
        action="disclose_confidential",
        session_id="sess_cross",
        parameters={"resource": "confidential.txt"},
    )
    # Attempting to validate a disclosure token as send_email tool must fail
    assert validate_and_consume_challenge(
        token=tok_disclose,
        action="send_email",
        session_id="sess_cross",
        parameters={"recipient": "admin@example.com"},
    ) is False

    tok_tool = create_confirmation_challenge(
        action="send_email",
        session_id="sess_cross_2",
        parameters={"recipient": "admin@example.com", "message": "Notice"},
    )
    # Attempting to validate a tool token as disclose_confidential must fail
    assert validate_and_consume_challenge(
        token=tok_tool,
        action="disclose_confidential",
        session_id="sess_cross_2",
        parameters={"resource": "confidential.txt"},
    ) is False


def test_concurrent_token_redemption_atomic_single_use():
    """B.9: Verify that concurrent redemption attempts on the same token allow only exactly one winner."""
    token = create_confirmation_challenge(
        action="send_email",
        session_id="sess_concurrent",
        parameters={"recipient": "user@example.com"},
    )

    results = []
    num_threads = 10

    def attempt_redemption():
        return validate_and_consume_challenge(
            token=token,
            action="send_email",
            session_id="sess_concurrent",
            parameters={"recipient": "user@example.com"},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attempt_redemption) for _ in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    # Invariant: Exactly one thread succeeds, all other 9 threads fail
    assert results.count(True) == 1
    assert results.count(False) == num_threads - 1


def test_unauthorized_agent_confidential_lookup_halts_for_confirmation():
    """Verify that an unauthorized caller looking up confidential records halts with confirmation_required."""
    def mock_llm(messages):
        if len(messages) == 2:
            return json.dumps({
                "action": "tool_call",
                "tool": "database_read",
                "arguments": {"employee_id": "employee_001"}
            })
        return json.dumps({"action": "final_answer", "response": "Found confidential employee record."})

    # Ordinary caller lacking disclose:confidential
    unauth_context = SecurityContext(permissions=["tools:database_read"])
    result = run_agent_loop(
        user_input="Look up employee_001",
        security_context=unauth_context,
        llm_callable=mock_llm,
    )

    assert result["status"] == "confirmation_required"
    assert result["decision"] == "CONFIRM"
    assert result.get("confirmation_token") is not None
    assert "Found confidential employee record." not in result["response"]


def test_tool_result_confirm_and_block_never_leak_to_llm():
    """Verify that tool results with CONFIRM, BLOCK, or error decisions never leak raw data to LLM context."""
    recorded_messages = []

    def mock_llm(messages):
        recorded_messages.extend(messages)
        if len(messages) == 2:
            return json.dumps({
                "action": "tool_call",
                "tool": "calculator",
                "arguments": {"expression": "100+1"}
            })
        return json.dumps({"action": "final_answer", "response": "Completed."})

    # 1. When inspect_output returns CONFIRM for tool result -> Agent loop must halt immediately!
    with patch("app.agent.agent.inspect_output") as mock_inspect:
        mock_inspect.return_value = OutputInspectionResult(
            inspection_id="insp_confirm",
            destination="agent_context",
            decision=OutputDecision.CONFIRM,
            risk_score=70,
            detected_sensitivity="confidential",
            explanation="Tool result requires user approval before model ingestion",
            release_permitted=False,
        )

        res_confirm = run_agent_loop(
            user_input="Run calc",
            llm_callable=mock_llm,
        )
        assert res_confirm["status"] == "confirmation_required"
        assert res_confirm["decision"] == "CONFIRM"
        assert res_confirm.get("confirmation_token") is not None
        # Check that tool result was NEVER appended to LLM messages
        assert not any("101" in m.get("content", "") for m in recorded_messages)

    # 2. When inspect_output returns BLOCK for tool result -> Content replaced with safe blocked payload
    recorded_messages.clear()
    with patch("app.agent.agent.inspect_output") as mock_inspect:
        mock_inspect.return_value = OutputInspectionResult(
            inspection_id="insp_block",
            destination="agent_context",
            decision=OutputDecision.BLOCK,
            risk_score=90,
            detected_sensitivity="restricted",
            explanation="Tool result toxic context blocked",
            release_permitted=False,
        )

        res_block = run_agent_loop(
            user_input="Run calc",
            llm_callable=mock_llm,
        )
        # On second iteration, messages should have the safe blocked message, never raw 101
        tool_results = [m["content"] for m in recorded_messages if "[Untrusted Tool Result" in m.get("content", "")]
        assert len(tool_results) >= 1
        assert "101" not in tool_results[0]
        assert "Tool result blocked by output security policy" in tool_results[0]


def test_tool_result_inspection_exception_fails_closed():
    """Verify that an unexpected exception during tool result inspection fails closed without leaking raw output."""
    recorded_messages = []

    def mock_llm(messages):
        recorded_messages.extend(messages)
        if len(messages) == 2:
            return json.dumps({
                "action": "tool_call",
                "tool": "calculator",
                "arguments": {"expression": "25*4"}
            })
        return json.dumps({"action": "final_answer", "response": "Done."})

    with patch("app.firewall.output_firewall.scan_data_for_dlp", side_effect=RuntimeError("Scanner failure")):
        res = run_agent_loop(
            user_input="Calculate 25*4",
            llm_callable=mock_llm,
        )
        tool_results = [m["content"] for m in recorded_messages if "[Untrusted Tool Result" in m.get("content", "")]
        assert len(tool_results) >= 1
        assert "100" not in tool_results[0]
        assert "Tool result blocked by output security policy" in tool_results[0]


def test_client_facing_response_fields_contain_no_secrets():
    """Verify that entire serialized API response (including tool_calls arguments) contains no unredacted secrets."""
    # Run a mock agent that calls a tool with a synthetic SSN in arguments
    def mock_agent_loop(**kwargs):
        return {
            "status": "success",
            "response": "Operation completed successfully.",
            "decision": "ALLOW",
            "risk": 10,
            "tool_calls": [
                {
                    "tool": "web_search",
                    "arguments": {"query": "Search for person with SSN 999-12-3456 and key TEST-API-KEY-SECRET"},
                    "status": "success",
                    "decision": "ALLOW",
                    "risk": 10,
                }
            ],
            "output_inspection": {
                "decision": "ALLOW",
                "detected_sensitivity": "public",
                "findings": [],
            },
        }

    with patch("app.main.run_agent_loop", side_effect=mock_agent_loop):
        resp = client.post("/chat", json={"message": "Search public record"})
        assert resp.status_code == 200
        raw_json_str = resp.text

        # The raw secret values must NOT appear anywhere in the serialized API response
        assert "999-12-3456" not in raw_json_str
        assert "TEST-API-KEY-SECRET" not in raw_json_str

        # Verify arguments were sanitized
        data = resp.json()
        arg_query = data["tool_calls"][0]["arguments"]["query"]
        assert "[REDACTED_SSN]" in arg_query
        assert "[REDACTED_API_KEY]" in arg_query


def test_confirmation_token_full_lifecycle_and_scope_separation():
    """Verify complete confirmation lifecycle: challenge issuance, redemption, single-use, and scope isolation."""
    sid = "session_lifecycle_test"

    # Step 1: Initial request to send email triggers confirmation
    def mock_agent_loop_confirm(**kwargs):
        tok = create_confirmation_challenge(
            action="send_email",
            session_id=sid,
            parameters={"recipient": "security@company.com", "message": "Notice"},
        )
        return {
            "status": "confirmation_required",
            "response": "Action 'send_email' requires explicit confirmation.",
            "decision": "CONFIRM",
            "risk": 65,
            "confirmation_token": tok,
            "tool_calls": [],
        }

    with patch("app.main.run_agent_loop", side_effect=mock_agent_loop_confirm):
        resp1 = client.post(
            "/chat",
            json={"message": "Send notice to security", "correlation_id": sid},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["status"] == "confirmation_required"
        token = data1["confirmation_token"]
        assert token is not None

    # Step 2: User approves with the single-use token in the same session
    captured_context = []

    def mock_agent_loop_approved(**kwargs):
        ctx = kwargs.get("security_context")
        captured_context.append(ctx)
        # Verify generic email confirmation is absent (security invariant)
        assert ctx.is_action_confirmed("send_email") is False
        # Verify exact recipient and parameter confirmation is present
        expected_action = canonical_action_id(
            "send_email",
            {"recipient": "security@company.com", "message": "Notice"},
        )
        assert ctx.is_action_confirmed(expected_action) is True
        assert any(a.startswith("send_email:security@company.com:") for a in ctx.confirmed_actions)
        # Verify it did NOT grant disclosure confirmation or unrelated permissions
        assert ctx.is_disclosure_confirmed("confidential.txt") is False
        assert ctx.has_permission("disclose:confidential") is False
        return {
            "status": "success",
            "response": "Email dispatched.",
            "decision": "ALLOW",
            "risk": 20,
            "tool_calls": [],
        }

    with patch("app.main.run_agent_loop", side_effect=mock_agent_loop_approved):
        resp2 = client.post(
            "/chat",
            json={
                "message": "Send notice to security",
                "confirmation_token": token,
                "correlation_id": sid,
            },
        )
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "success"

    # Step 3: Replay attack: try using the exact same token a second time
    with patch("app.main.run_agent_loop", side_effect=mock_agent_loop_confirm):
        resp3 = client.post(
            "/chat",
            json={
                "message": "Send notice to security",
                "confirmation_token": token,  # Replayed token
                "correlation_id": sid,
            },
        )
        assert resp3.status_code == 200
        # Must halt for confirmation again because token was consumed!
        assert resp3.json()["status"] == "confirmation_required"


def test_mixed_source_provenance_elevates_to_highest_sensitivity():
    """Verify that multiple provenance records preserve the highest sensitivity without downgrade."""
    p_public = create_tool_provenance("calculator", {"expression": "1+1"})
    p_internal = create_tool_provenance("send_email", {"recipient": "internal@company.com"})
    p_confidential = create_tool_provenance("file_read", {"filename": "confidential.txt"})

    # Elevation preserves highest rank: confidential > internal > public
    elevated = elevate_provenance([p_public, p_internal, p_confidential])
    assert elevated.sensitivity == "confidential"
    assert elevated.source_tool == "file_read"
    assert elevated.source_resource == "confidential.txt"
    assert elevated.required_permission == "disclose:confidential"


