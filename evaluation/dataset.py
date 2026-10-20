import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ScenarioCategory(str, Enum):
    BENIGN_INFO = "benign_info"
    BENIGN_CALC = "benign_calc"
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_OVERRIDE = "system_override"
    UNAUTHORIZED_TOOL = "unauthorized_tool"
    INVALID_ARGUMENTS = "invalid_arguments"
    CONFIDENTIAL_DATABASE = "confidential_database"
    SENSITIVE_FILE = "sensitive_file"
    MULTISTEP_EXFILTRATION = "multistep_exfiltration"
    UNTRUSTED_CONTENT_CHAIN = "untrusted_content_chain"
    CREDENTIAL_PII_LEAK = "credential_pii_leak"
    PARAPHRASED_DISCLOSURE = "paraphrased_disclosure"
    MIXED_PROVENANCE = "mixed_provenance"
    CONFIRMATION_FORGERY = "confirmation_forgery"
    MALFORMED_RESPONSE = "malformed_response"
    LEGITIMATE_MULTITOOL = "legitimate_multitool"


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ExpectedSecurityOutcome(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CONFIRM = "CONFIRM"


class ExpectedDisclosureOutcome(str, Enum):
    NO_DISCLOSURE = "NO_DISCLOSURE"
    SAFE_DISCLOSURE = "SAFE_DISCLOSURE"
    UNAUTHORIZED_DISCLOSURE = "UNAUTHORIZED_DISCLOSURE"


class Scenario(BaseModel):
    scenario_id: str = Field(..., description="Unique and stable identifier for scenario")
    category: ScenarioCategory = Field(..., description="Evaluation category")
    is_attack: bool = Field(..., description="Ground-truth attack label (True if malicious/violation, False if benign)")
    user_request: str = Field(..., description="User prompt provided to the agent/gateway")
    mock_model_steps: List[Dict[str, Any]] = Field(
        ...,
        description="Deterministic list of mock model actions (tool calls or final answers)",
    )
    expected_security_outcome: ExpectedSecurityOutcome = Field(
        ..., description="Expected security policy decision: ALLOW, BLOCK, or CONFIRM"
    )
    expected_disclosure_outcome: ExpectedDisclosureOutcome = Field(
        ..., description="Expected disclosure outcome: NO_DISCLOSURE, SAFE_DISCLOSURE, UNAUTHORIZED_DISCLOSURE"
    )
    applicable_configurations: List[str] = Field(
        default=["unprotected", "baseline", "raphael", "ablated"],
        description="Configurations to run this scenario against",
    )
    ground_truth_rationale: str = Field(..., description="Explanation of why this ground truth is assigned")
    severity: SeverityLevel = Field(default=SeverityLevel.LOW, description="Severity rating")
    security_context: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional caller security context (permissions, user_id, confirmed_actions)"
    )
    unauthorized_tool_attempted: Optional[str] = Field(
        default=None, description="Name of unauthorized tool attempted, if any"
    )
    sensitive_data_targeted: Optional[str] = Field(
        default=None, description="Type of sensitive data targeted, if any"
    )

    @field_validator("mock_model_steps")
    @classmethod
    def validate_steps(cls, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not steps:
            raise ValueError("Scenario must define at least one mock model step")
        for idx, step in enumerate(steps):
            if "action" not in step:
                raise ValueError(f"Step {idx} missing 'action' field")
            if step["action"] not in ("tool_call", "final_answer", "raw_text"):
                raise ValueError(f"Step {idx} invalid action '{step['action']}'")
        return steps


def load_scenarios(filepath: str | Path = Path("evaluation/scenarios.jsonl")) -> List[Scenario]:
    """Load and validate scenarios from JSON Lines file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Scenario dataset file not found: {path}")

    scenarios: List[Scenario] = []
    seen_ids = set()

    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            try:
                data = json.loads(line_str)
                scenario = Scenario(**data)
                if scenario.scenario_id in seen_ids:
                    raise ValueError(f"Duplicate scenario_id '{scenario.scenario_id}' at line {line_num}")
                seen_ids.add(scenario.scenario_id)
                scenarios.append(scenario)
            except Exception as e:
                raise ValueError(f"Error parsing scenario at line {line_num}: {e}") from e

    return scenarios


def validate_dataset(scenarios: List[Scenario], min_scenarios: int = 100) -> Dict[str, Any]:
    """Validate dataset properties across categories, balance, and completeness."""
    if len(scenarios) < min_scenarios:
        raise ValueError(f"Dataset has {len(scenarios)} scenarios, expected at least {min_scenarios}")

    category_counts: Dict[str, int] = {}
    attack_count = 0
    benign_count = 0

    for s in scenarios:
        category_counts[s.category.value] = category_counts.get(s.category.value, 0) + 1
        if s.is_attack:
            attack_count += 1
        else:
            benign_count += 1

    missing_categories = [cat.value for cat in ScenarioCategory if cat.value not in category_counts]
    if missing_categories:
        raise ValueError(f"Dataset missing categories: {missing_categories}")

    return {
        "total_scenarios": len(scenarios),
        "attack_count": attack_count,
        "benign_count": benign_count,
        "category_counts": category_counts,
        "categories_represented": len(category_counts),
    }
