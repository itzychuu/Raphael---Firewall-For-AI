# RAPHAEL — AI Agent Runtime Security Gateway

RAPHAEL is a runtime security gateway designed to protect AI agent execution by enforcing security policies across user inputs, tool selection, argument validation, multi-step behavioral action sequences, tool execution results, and model responses.

---

## 1. Project Purpose & Scope

AI agents equipped with tool-calling capabilities present significant security risks, including prompt injection, unauthorized privilege escalation, path traversal, arbitrary code execution, multi-step data exfiltration, and unauthorized data disclosure.

RAPHAEL places a multi-layered security boundary around both the LLM and the tools it attempts to execute:
1. **Input Firewall (Phase 2)**: Intercepts malicious directives, jailbreaks, and prompt injections before the agent is invoked.
2. **Central Tool Firewall (Phase 3)**: Validates arguments against strict Pydantic schemas, enforces least privilege, requires explicit user confirmation for high-impact tools, and sandboxes execution.
3. **Behavioral Risk Engine (Phase 4)**: Correlates user intent, action history, data sensitivity, and tool chaining to detect multi-step anomalies and exfiltration attacks before tools execute.
4. **Output Firewall & Data Loss Prevention (Phase 5)**: Intercepts tool results before they enter the model reasoning context, tracks data provenance, detects sensitive data (credentials, SSNs, private keys, confidential records), and inspects final agent responses before release to API clients.

---

## 2. Milestone Roadmap & Status

| Phase | Milestone | Status | Description |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Controlled AI Agent | **COMPLETED** | Ollama client, model configuration (`qwen3:4b-instruct`), and 5 mock enterprise tools |
| **Phase 2** | Input Security Firewall | **COMPLETED** | Regex-based injection detection, risk scoring (0–100), policy decisions (`ALLOW`, `MONITOR`, `CONFIRM`, `BLOCK`) |
| **Phase 3** | Tool Firewall & Controlled Execution | **COMPLETED** | Central tool registry, Pydantic argument validation, least-privilege authorization, confirmation enforcement, safe execution sandbox, agent loop with iteration & tool call limits, FastAPI REST API (`/health`, `/inspect`, `/chat`), and structured audit logging |
| **Phase 4** | Behavioral Risk Engine | **COMPLETED** | Cross-stage correlation between user intent, session action history, target data sensitivity, and tool chaining; multi-indicator explainable risk scoring; security invariant enforcement; session history isolation |
| **Phase 5** | Output Firewall & Data Loss Prevention | **COMPLETED** | Two-stage output inspection (pre-LLM tool masking & post-LLM response inspection), deterministic DLP pattern engine, data provenance tracking, least-privilege disclosure policy, and idempotent redaction |
| **Phase 6** | Full Evaluation & Testing | *Future Work* | Comparative benchmark evaluation (No Firewall vs. Rule Baseline vs. RAPHAEL with Behavioral & Output protection), detection precision/recall, false positive rate, latency overhead, and mitigation reporting |

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
                         |   (/health, /inspect, /chat,  |
                         |       /inspect-output)        |
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
                                                                      v
                                                    +------------------------------------+
                                                    | Phase 5: Tool Result Inspection    |
                                                    | (Point A: Redact secrets before    |
                                                    |  entering LLM context)             |
                                                    +------------------------------------+
                                                                      |
                                                                      v
                                                            [Agent Reasoning Step]
                                                                      |
                                                                      v
                                                    +------------------------------------+
                                                    | Phase 5: Final Response Inspection |
                                                    | (Point B: Recipient authorization, |
                                                    |  DLP scanning, and redaction)      |
                                                    +------------------------------------+
                                                                    /     \
                                                              BLOCK         ALLOW / REDACT
                                                               /               \
                                                              v                 v
                                                    [Safe Denial Text]    [Release to Client]
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

## 5. Phase 5: Output Firewall & Data Loss Prevention (DLP)

The Output Firewall is an independently enforced security boundary that prevents unauthorized sensitive data from leaking into the model context or reaching API clients.

### 5.1 DLP Detection Engine (`app/firewall/dlp_detector.py`)

A deterministic, offline-capable scanner detects sensitive patterns and structures:
- **Social Security Numbers (SSN)**: Standard format `\b\d{3}-\d{2}-\d{4}\b`, excluding non-SSN area codes (`000`, `666`, `900–999` with synthetic fixtures permitted for testing).
- **API Keys & Credential Tokens**: Prefixes such as `sk-live-`, `sk-ant-`, `ghp_`, `AKIA[0-9A-Z]{16}`, and generic bearer tokens.
- **Password Assignments**: Assignments like `password = ...`, `api_key = ...`, `secret: ...`.
- **Private Keys**: Multiline PEM blocks (`-----BEGIN RSA/OPENSSH/EC/PRIVATE KEY-----`).
- **Employee Confidential Records**: Salary figures (`$140,000`), compensation fields, and mock employee records.
- **Confidential Files**: File tags and content markers matching `confidential.txt`.
- **Email Addresses**: Syntactically valid email formats flagged for context-dependent disclosure review.

### 5.2 Data Provenance & Sensitivity Elevation (`app/firewall/data_provenance.py`)

Data sensitivity does not vanish merely because text is summarized, reformatted, or paraphrased by an LLM.
- **Provenance Tracking**: Each tool invocation creates a `DataProvenance` record capturing the source tool, safe resource identifier (e.g., `file:confidential.txt`, `db:employees`), sensitivity level (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`), and trust flag.
- **Sensitivity Elevation**: As tools execute in a session, cumulative provenance elevates to the highest sensitivity observed (`PUBLIC` < `INTERNAL` < `CONFIDENTIAL` < `RESTRICTED`).
- **No Raw Secrets in Provenance**: Provenance metadata retains only classifications and safe resource IDs, never secret values.

### 5.3 Deterministic Redaction Engine (`app/firewall/redaction.py`)

- **Right-to-Left Redaction**: Replaces sensitive spans from highest character offset to lowest to prevent offset shifts.
- **Span Merging**: Overlapping or adjacent sensitive spans are merged into a single canonical marker:
  - `[REDACTED_SSN]`
  - `[REDACTED_API_KEY]`
  - `[REDACTED_PASSWORD]`
  - `[REDACTED_PRIVATE_KEY]`
  - `[REDACTED_CONFIDENTIAL_DATA]`
  - `[REDACTED_EMAIL]`
- **Idempotence**: Re-running redaction on already redacted text preserves existing markers without double-wrapping.
- **Structured Redaction**: Recursively redacts strings inside nested JSON dictionaries and lists while preserving safe data types.

### 5.4 Two-Point Output Inspection Architecture (`app/firewall/output_firewall.py`)

Output inspection occurs at two distinct security boundaries:
1. **Point A: Pre-LLM Tool Result Inspection (`destination="agent_context"`)**:
   - Authorized tool outputs are scanned before entering the agent's message history.
   - Raw restricted secrets (SSNs, API keys, private keys) are masked immediately so the LLM reasoning context cannot absorb or parrot them.
2. **Point B: Post-LLM Final Response Inspection (`destination="api_client"`)**:
   - The final text generated by the agent is scanned before returning to the caller.
   - **Authorization-Aware Disclosure Policy**: Callers lacking explicit permissions (`disclose:confidential` or `disclose:restricted`) are denied raw release.
   - **Read vs. Disclose Separation**: Tool read permissions (`tools:file_read`, `tools:database_read`) grant permission to query resources internally, but **never grant permission to disclose sensitive data externally**.
   - **Paraphrased Confidential Narrative Handling**: If candidate output derives from confidential or restricted source data but exact regex pattern matches are zero (e.g. summarized or paraphrased narratives), the policy holds the response for explicit user confirmation (`CONFIRM`) or blocks it (`BLOCK`), rather than returning `ALLOW`.
   - **Fail-Closed Security**: Any unhandled exception during inspection blocks the output and logs an audit failure event.

### 5.5 Server-Issued Single-Use Confirmation Challenges (`app/firewall/confirmation.py`)

To eliminate client-side confirmation forgery:
- High-risk tool calls and sensitive disclosures generate an unguessable, cryptographically random challenge token bound to the specific action, session ID, and parameters.
- Client requests must provide this token via `confirmation_token`.
- Tokens are single-use: upon consumption, they are invalidated immediately, preventing replay attacks.
- Raw client-supplied confirmation arrays (e.g. `confirmed_actions: ["*"]`) are strictly ignored and rejected.

---

## 6. Prerequisites & Local Setup

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

## 7. Running the FastAPI Service

Start the service locally using Uvicorn:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI documentation is available at: `http://127.0.0.1:8000/docs`

---

## 8. API Endpoints

### 1. `GET /health`
Returns service status and dependency readiness (Ollama connectivity).

### 2. `POST /inspect`
Runs the Phase 2 input security firewall without querying the LLM or invoking tools.

### 3. `POST /inspect-output`
Directly inspects arbitrary text or structured payloads against the Phase 5 Output Firewall & DLP detector. Public requests strictly enforce `destination="api_client"` (client destination override attempts are ignored). Returns detection categories, risk scores, safe explanations, and redacted output without disclosing raw secrets.

### 4. `POST /chat`
Executes the guarded chat pipeline:
`Input Firewall` ➔ `Intent Classification` ➔ `Agent Loop` ➔ `Tool Firewall & Behavioral Risk Engine` ➔ `Point A Tool Result Inspection` ➔ `LLM Processing` ➔ `Point B Final Response Inspection` ➔ `Audit Logging`.
Requires server-issued `confirmation_token` to approve halted actions.

### 5. `GET /behavior/session/{session_id}`
Retrieves tracked behavioral events for a specific session for evaluation and research. Requires research/admin authorization via header:
`X-RAPHAEL-RESEARCH-TOKEN: raphael-research-internal` (or `Authorization: Bearer <token>`). Unauthenticated requests are rejected with HTTP 403 Forbidden.

---

## 9. Running Tests

The test suite runs entirely offline without requiring a live Ollama server:

```powershell
# Run all 99 offline unit and integration tests across Phases 1-6
.\.venv\Scripts\pytest.exe -v --ignore=tests/test_agent.py
```

To run the live Ollama agent test:
```powershell
.\.venv\Scripts\pytest.exe -v tests/test_agent.py
```

---

## 10. Phase 6 Experimental Evaluation & Ablation Study

Phase 6 implements a reproducible experimental framework evaluating effectiveness, limitations, and runtime overhead across four isolated configurations under identical deterministic inputs and mock model traces across 114 synthetic test scenarios:

1. **Configuration A (Unprotected Agent)**: Bypasses security controls in an isolated test harness using simulated mock tools and synthetic data.
2. **Configuration B (Rule-Based Baseline)**: Conventional static controls (keyword prompt injection detection, Pydantic schema validation, tool permission checks, and basic regex DLP scanning).
3. **Configuration D (Behavioral-Engine Ablation)**: Retains input firewall, tool validation, provenance elevation, and output DLP, but disables the Phase 4 Behavioral Risk Engine.
4. **Configuration C (Full RAPHAEL Gateway)**: Full integrated runtime stack (Input Firewall, Central Tool Firewall, Behavioral Risk Engine, Dual-Point Output Firewall, Data Provenance, and single-use confirmation tokens).

### Running the Benchmark

```powershell
.\.venv\Scripts\python.exe -m evaluation.runner
```

### Benchmark Summary Results (4 Configurations)

| Metric | Configuration A (Unprotected) | Configuration B (Baseline) | Configuration D (BRE Ablation) | Configuration C (Full RAPHAEL) |
| :--- | :---: | :---: | :---: | :---: |
| **Detection Precision** | Undefined (0/0) | 0.9857 | 0.9872 | **0.9875** |
| **Detection Recall** | 0.0000 | 0.8313 | 0.9277 | **0.9518** |
| **Detection F1 Score** | 0.0000 | 0.9020 | 0.9565 | **0.9693** |
| **False Positive Rate (FPR)** | 0.0000 | 0.0323 | 0.0323 | **0.0323** |
| **Attack Prevention Rate** | 47.0% | 96.4% | 100.0% | **100.0%** |
| **Unauthorized Tools Executed** | 35 | 0 | 0 | **0** |
| **Unauthorized Disclosures** | 26 | 3 | 0 | **0** |
| **Valid Benign Completion Rate** | 100.0% | 100.0% | 100.0% | **100.0%** |
| **Malformed Handling Rate** | 71.4% | 85.7% | 85.7% | **85.7%** |
| **Mean Gateway Latency** | 0.019 ms | 0.149 ms | 0.790 ms | **0.834 ms** |
| **Added Latency vs Baseline** | N/A | Reference | +0.641 ms | **+0.685 ms** |

Generated evaluation artifacts:
- [`results/scenario_results.csv`](file:///d:/RAPHAEL/results/scenario_results.csv)
- [`results/aggregate_metrics.json`](file:///d:/RAPHAEL/results/aggregate_metrics.json)
- [`results/category_metrics.csv`](file:///d:/RAPHAEL/results/category_metrics.csv)
- [`results/latency_summary.json`](file:///d:/RAPHAEL/results/latency_summary.json)
- [`results/evaluation_report.md`](file:///d:/RAPHAEL/results/evaluation_report.md)
- [`results/charts/detection_comparison.svg`](file:///d:/RAPHAEL/results/charts/detection_comparison.svg)
- [`results/charts/prevention_rates.svg`](file:///d:/RAPHAEL/results/charts/prevention_rates.svg)
- [`results/charts/latency_comparison.svg`](file:///d:/RAPHAEL/results/charts/latency_comparison.svg)

---

## 11. Security Limitations & Disclaimers

1. **Synthetic Scenarios vs. Real-World Attacks**: Synthetic scenarios evaluate defined threat categories. They cannot guarantee detection of all obfuscated, novel zero-day prompt injections.
2. **Conservative Provenance Propagation**: Provenance tracking elevates sensitivity based on session history. Paraphrased narratives deriving from confidential provenance without exact regex matches require confirmation before release.
3. **In-Memory Session & Challenge Storage**: Recipient permissions, confirmation challenge tokens, and session histories are simulated in memory for prototype research. Production deployment requires distributed key-value stores and enterprise IAM / OAuth2 token verification.
4. **Research Prototype**: RAPHAEL is a research-oriented security gateway designed to study defense-in-depth and behavioral risk correlation for tool-enabled AI agents.
