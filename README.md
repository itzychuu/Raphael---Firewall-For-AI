# RAPHAEL — AI Agent Runtime Security Gateway

RAPHAEL is a runtime security gateway designed to protect AI agent execution by enforcing security policies across user inputs, tool selection, argument validation, multi-step behavioral action sequences, execution boundaries, and audit logging.

---

## 1. Project Purpose & Scope

AI agents equipped with tool-calling capabilities present significant security risks, including prompt injection, unauthorized privilege escalation, path traversal, arbitrary code execution, and multi-step data exfiltration.

RAPHAEL places a multi-layered security boundary around both the LLM and the tools it attempts to execute:
1. **Input Firewall (Phase 2)**: Intercepts malicious directives, jailbreaks, and prompt injections before the agent is invoked.
2. **Central Tool Firewall (Phase 3)**: Validates arguments against strict Pydantic schemas, enforces least privilege, requires explicit user confirmation for high-impact tools, and sandboxes execution.
3. **Behavioral Risk Engine (Phase 4)**: Correlates user intent, action history, data sensitivity, and tool chaining to detect multi-step anomalies and exfiltration attacks before tools execute.

---

## 2. Milestone Roadmap & Status

| Phase | Milestone | Status | Description |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Controlled AI Agent | **COMPLETED** | Ollama client, model configuration (`qwen3:4b-instruct`), and 5 mock enterprise tools |
| **Phase 2** | Input Security Firewall | **COMPLETED** | Regex-based injection detection, risk scoring (0–100), policy decisions (`ALLOW`, `MONITOR`, `CONFIRM`, `BLOCK`) |
| **Phase 3** | Tool Firewall & Controlled Execution | **COMPLETED** | Central tool registry, Pydantic argument validation, least-privilege authorization, confirmation enforcement, safe execution sandbox, agent loop with iteration & tool call limits, FastAPI REST API (`/health`, `/inspect`, `/chat`), and structured audit logging |
| **Phase 4** | Behavioral Risk Engine | **COMPLETED** | Cross-stage correlation between user intent, session action history, target data sensitivity, and tool chaining; multi-indicator explainable risk scoring; security invariant enforcement; session history isolation |
| **Phase 5** | Dedicated Output Firewall | *Future Work* | Data Loss Prevention (DLP), output token sanitization, and PII/secret scrubbing before user delivery |
| **Phase 6** | Enterprise Policy & Evaluation | *Future Work* | Benchmark evaluation against labeled attack datasets, external policy engines, distributed auditing, and RBAC directory integrations |

---

## 3. Architecture & Request Pipeline

```
                     +---------------------------------------+
                     |             Client Request            |
                     +---------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |      FastAPI REST Gateway     |
                         |   (/health, /inspect, /chat)  |
                         +-------------------------------+
                                         |
                                         v
                      +-------------------------------------+
                      |       Phase 2: Input Firewall       |
                      |   - Prompt Injection Detection      |
                      |   - Risk Scoring & Policy Decision  |
                      +-------------------------------------+
                                    /        \
                    BLOCK or CONFIRM          ALLOW or MONITOR
                           /                            \
                          v                              v
            [Return Blocked/Confirm]           +-------------------+
                                               | Controlled Agent  |
                                               |  Execution Loop   |
                                               +-------------------+
                                                         |
                                                  Model Requests
                                                    Tool Call
                                                         |
                                                         v
                                      +------------------------------------+
                                      |     Phase 3: Central Tool Firewall |
                                      |  1. Tool Registry Verification     |
                                      |  2. Least-Privilege Authorization  |
                                      |  3. Pydantic Argument Validation   |
                                      +------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |   Phase 4: Behavioral Risk Engine  |
                                      |  4. Intent & Sensitivity Analysis  |
                                      |  5. Multi-Indicator Correlation    |
                                      |  6. Decision Combination & Policy  |
                                      +------------------------------------+
                                                    /        \
                                      CONFIRM/BLOCK            ALLOW/MONITOR
                                            /                        \
                                           v                          v
                             [Halt Action Execution]        [Execute Mock Tool]
                                                                      |
                                                          Untrusted Result Appended
                                                                      |
                                                                      v
                                                            [Agent Final Answer]
                                                                      |
                                                                      v
                                                          +------------------------+
                                                          | Structured Audit Event |
                                                          +------------------------+
```

---

## 4. Phase 4: Behavioral Risk Engine

The Behavioral Risk Engine addresses the central research question:
> *"Can cross-stage behavioral correlation between user intent, action history, tool usage, authorization context, and data sensitivity improve runtime detection of multi-step attacks in tool-enabled AI agents?"*

### 4.1 Behavioral Indicators & Scoring Weights

The engine computes an explainable, deterministic score (0–100) combining configured indicator weights:

| Indicator | Weight | Description |
| :--- | :---: | :--- |
| `action_outside_request_scope` | +25 | Proposed tool does not align with the classified user intent (e.g. calculation request prompting file reading). |
| `sensitive_resource_without_justification` | +35 | Agent attempts to read `CONFIDENTIAL` or `RESTRICTED` resources without a matching request intent. |
| `suspicious_action_sequence` / `sensitive_data_movement` | +45 | High-risk sequencing: reading sensitive data (`confidential.txt` or database records) followed by an outbound communication attempt (`send_email`). |
| `repeated_denied_actions` | +20 (cap 40) | Multiple previously denied or blocked actions detected in the current session. |
| `untrusted_content_followed_by_sensitive_action` | +30 | An external content fetch (`web_search` or `file_read`) immediately followed by an action targeting sensitive resources. |
| `unusual_tool_chain` | +20 | Anomalous transitions between disparate tool types (e.g. `calculator` directly transitioning into `send_email`, `database_read`, or `file_read`). |
| `excessive_tool_activity` | +15 | Excessive cumulative tool executions (>= 4 tools) within a single session. |

### 4.2 Decision Thresholds & Invariant Combination

- `0 – 25`: **ALLOW**
- `26 – 50`: **MONITOR**
- `51 – 75`: **CONFIRM**
- `76 – 100`: **BLOCK**

#### Security Invariants:
1. **Phase 3 Authorization is Authoritative**: A Phase 3 `BLOCK` (unregistered tool, permission denied, argument validation failure) can **never** be downgraded by a low behavioral score.
2. **Confirmation Monotonicity**: A Phase 3 `CONFIRM` (e.g. outbound email) can **never** be downgraded to `ALLOW` or `MONITOR`.
3. **Escalation Priority**: If the Behavioral Risk Engine detects elevated risk (e.g. score >= 76), the final decision escalates to `BLOCK`, halting execution immediately.
4. **Fail-Safe Behavior**: Any internal error in behavioral evaluation applies a conservative fail-safe policy, never failing open.

---

## 5. Prerequisites & Local Setup

### Requirements
- Python 3.12+
- Windows, macOS, or Linux
- (Optional for live LLM execution) [Ollama](https://ollama.ai/) with model `qwen3:4b-instruct`

### Installation
Activate the virtual environment:
```powershell
.\.venv\Scripts\Activate.ps1
```

Or install dependencies:
```bash
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

---

## 6. Running the FastAPI Service

Start the service locally using Uvicorn:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI documentation is available at: `http://127.0.0.1:8000/docs`

---

## 7. API Endpoints

### 1. `GET /health`
Returns service status and dependency readiness (Ollama connectivity).

### 2. `POST /inspect`
Runs the input security firewall without querying the LLM or invoking tools.

### 3. `POST /chat`
Executes the guarded chat pipeline (Input Firewall ➔ Intent Classification ➔ Agent Loop ➔ Tool Firewall & Behavioral Risk Engine ➔ Audit Event).

### 4. `GET /behavior/session/{session_id}`
Inspects chronological behavioral events tracked for a specific session for evaluation and research.

---

## 8. Running Tests

The test suite runs entirely offline without requiring a live Ollama server:

```powershell
# Run all 55 offline unit and integration tests
.\.venv\Scripts\pytest.exe -v tests/test_input_firewall.py tests/test_tools.py tests/test_tool_firewall.py tests/test_agent_loop.py tests/test_api.py tests/test_behavioral_engine.py
```

To run the live Ollama agent test:
```powershell
.\.venv\Scripts\pytest.exe -v tests/test_agent.py
```

---

## 9. Current Security Limitations

1. **Deterministic Baseline Intent Classification**: The current prototype uses a deterministic keyword/syntax taxonomy with explicit confidence scores. More complex semantic intent models can be explored in future milestones.
2. **In-Memory Session History**: Session histories are bounded and isolated in thread-safe memory. Distributed or persistent session storage is planned for Phase 6.
3. **Dedicated Output Firewall**: Phase 5 remains responsible for full model output Data Loss Prevention (DLP) and output token filtering.
