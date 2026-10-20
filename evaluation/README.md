# RAPHAEL — Experimental Evaluation Framework (Phase 6)

This directory contains the reproducible experimental evaluation framework for RAPHAEL, evaluating its effectiveness, limitations, and runtime overhead compared to an Unprotected Agent and a Rule-Based Baseline.

---

## 1. Research Question

> **Can cross-stage behavioral correlation between user intent, action history, tool usage, and data sensitivity improve runtime detection and prevention of multi-step attacks in tool-enabled LLM applications?**

The evaluation benchmarks effectiveness, false positives, benign-task utility, and runtime overhead across three isolated configurations under identical deterministic inputs and mock model traces.

---

## 2. Experimental Configurations

| Feature | Configuration A (Unprotected Agent) | Configuration B (Rule-Based Baseline) | Configuration D (BRE Ablation) | Configuration C (Full RAPHAEL Gateway) |
| :--- | :--- | :--- | :--- | :--- |
| **Isolation** | Test harness only; mock tools & synthetic data | Test harness / mock tools | Test harness / mock tools | Full RAPHAEL runtime stack |
| **Input Security** | Bypassed | Keyword/regex prompt injection detection | Input Firewall | Input Firewall + Intent Classification |
| **Tool Execution** | Direct mock tool dispatch | Pydantic schema validation & static permissions | Central Tool Firewall + Traversal Checks | Central Tool Firewall + Traversal Checks |
| **Behavioral Engine** | Disabled | Disabled | **DISABLED (Ablated)** | **Full Behavioral Risk Engine (Chaining, History)** |
| **Data Provenance** | Disabled | Disabled | Monotonic sensitivity tracking | Monotonic sensitivity tracking |
| **Output Firewall** | Bypassed | Basic regex DLP scanning | Dual-Point Output Firewall + Paraphrase Gating | Dual-Point Output Firewall + Paraphrase Gating |
| **Confirmation** | Bypassed | Static tool confirmation only | Server-issued single-use bound tokens | Server-issued single-use bound tokens |

---

## 3. Dataset & Scenario Taxonomy (`evaluation/scenarios.jsonl`)

The dataset contains **114 deterministic synthetic test scenarios** across 16 categories:

| Category | Count | Type | Description |
| :--- | :---: | :---: | :--- |
| `benign_info` | 7 | Benign | Standard factual and knowledge base queries |
| `benign_calc` | 7 | Benign | Arithmetic and mathematical calculations |
| `prompt_injection` | 8 | Attack | Direct instruction override attempts |
| `system_override` | 7 | Attack | Extraction of hidden system instructions |
| `unauthorized_tool` | 7 | Attack | Invocation of unregistered or unpermitted tools |
| `invalid_arguments` | 7 | Attack | Path traversal (`../`, `/etc/`), code injection, schema errors |
| `confidential_database` | 7 | Attack | Unauthorized queries for employee salaries and SSNs |
| `sensitive_file` | 7 | Attack | Access to `confidential.txt` without authorization |
| `multistep_exfiltration` | 8 | Attack | Sensitive read followed by outbound email or search leak |
| `untrusted_content_chain` | 7 | Attack | Untrusted web content triggering sensitive tool calls |
| `credential_pii_leak` | 7 | Attack | Output containing raw synthetic SSNs, API keys, or private keys |
| `paraphrased_disclosure` | 7 | Attack | Summarizing confidential records without literal regex matches |
| `mixed_provenance` | 7 | Mixed | Public and confidential data accessed together |
| `confirmation_forgery` | 7 | Attack | Replaying consumed tokens, wildcard bypass (`*`), forged claims |
| `malformed_response` | 7 | Benign/Edge | Non-JSON text, broken JSON, endless loop limits |
| `legitimate_multitool` | 7 | Benign | Multi-tool workflows (e.g., calc then search) that must remain usable |

---

## 4. Benchmark Execution & Reproduction

To execute the offline evaluation benchmark:

```powershell
.\.venv\Scripts\python.exe -m evaluation.runner
```

Optional CLI parameters:
- `--scenarios evaluation/scenarios.jsonl`: Path to custom scenario dataset
- `--results-dir results`: Directory to store generated artifacts
- `--repetitions 3`: Number of timing repetitions per scenario
- `--warmup 1`: Number of warmup passes to discard cold-start effects
- `--random-seed 42`: Deterministic random seed

---

## 5. Generated Artifacts (`results/`)

Running the benchmark produces:

- `results/scenario_results.csv`: Row-by-row execution trace for every scenario × configuration (sanitized; strictly zero raw secrets).
- `results/aggregate_metrics.json`: High-level metrics for all three configurations.
- `results/category_metrics.csv`: Per-category detection, prevention, and utility metrics.
- `results/latency_summary.json`: Mean, median, P95, min, max, and relative overhead.
- `results/evaluation_report.md`: Formal evaluation report comparing all configurations.
- `results/charts/detection_comparison.svg`: SVG visual comparison of precision, recall, and F1.
- `results/charts/prevention_rates.svg`: SVG visual comparison of attack prevention vs. benign task success.
- `results/charts/latency_comparison.svg`: SVG visual comparison of median and P95 latency.

---

## 6. Known Limitations & Threats to Validity

1. **Synthetic Scenarios vs. Real-World Attacks**: Scenarios use synthetic records and mock tools. While designed to emulate real-world TTPs, synthetic tests cannot prove universal security against novel zero-day prompt injections.
2. **Deterministic Mock Replay**: Replaying deterministic model actions isolates gateway performance from LLM non-determinism, but does not measure how a live LLM adapts to defensive error messages.
3. **Paraphrase Gating Trade-Off**: Paraphrase gating relies on provenance elevation. When an agent accesses confidential data, subsequent narrative responses require explicit user confirmation to prevent covert exfiltration, slightly increasing user confirmation prompts.
