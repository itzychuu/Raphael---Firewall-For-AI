import json
from typing import Any, List, Set, Tuple
from app.models.schemas import DLPFinding, DLPFindingCategory

REDACTION_MARKERS = {
    DLPFindingCategory.SSN: "[REDACTED_SSN]",
    DLPFindingCategory.API_KEY: "[REDACTED_API_KEY]",
    DLPFindingCategory.PASSWORD: "[REDACTED_PASSWORD]",
    DLPFindingCategory.PRIVATE_KEY: "[REDACTED_PRIVATE_KEY]",
    DLPFindingCategory.EMPLOYEE_RECORD: "[REDACTED_CONFIDENTIAL_DATA]",
    DLPFindingCategory.CONFIDENTIAL_FILE: "[REDACTED_CONFIDENTIAL_DATA]",
    DLPFindingCategory.EMAIL_ADDRESS: "[REDACTED_EMAIL]",
}


def merge_overlapping_findings(findings: List[DLPFinding]) -> List[DLPFinding]:
    """Merge or filter overlapping DLP finding spans, keeping the largest/most sensitive range."""
    if not findings:
        return []

    # Sort primarily by start ascending, then length descending
    sorted_findings = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    merged: List[DLPFinding] = []

    current = sorted_findings[0]

    for next_finding in sorted_findings[1:]:
        if next_finding.start < current.end:
            # Overlapping span: extend end if next_finding goes further
            if next_finding.end > current.end:
                current = DLPFinding(
                    category=current.category,
                    start=current.start,
                    end=next_finding.end,
                    matched_text_length=next_finding.end - current.start,
                    sensitivity=current.sensitivity,
                    description=f"{current.description} (merged)",
                )
        else:
            merged.append(current)
            current = next_finding

    merged.append(current)
    return merged


def redact_text(text: str, findings: List[DLPFinding], categories_to_redact: Set[DLPFindingCategory] = None) -> str:
    """Deterministically redact detected spans in text with canonical security markers."""
    if not text or not findings:
        return text

    target_findings = [
        f for f in findings
        if categories_to_redact is None or f.category in categories_to_redact
    ]

    if not target_findings:
        return text

    non_overlapping = merge_overlapping_findings(target_findings)

    # Reconstruct string by applying replacements from right to left (preserves indices)
    result = list(text)
    for finding in sorted(non_overlapping, key=lambda f: f.start, reverse=True):
        marker = REDACTION_MARKERS.get(finding.category, "[REDACTED_DATA]")
        result[finding.start:finding.end] = list(marker)

    return "".join(result)


def redact_structured_data(
    data: Any,
    findings: List[DLPFinding],
    categories_to_redact: Set[DLPFindingCategory] = None,
) -> Any:
    """Apply redaction to text or structured dictionary/list data."""
    if isinstance(data, str):
        return redact_text(data, findings, categories_to_redact)
    elif isinstance(data, (dict, list)):
        serialized = json.dumps(data)
        redacted_serialized = redact_text(serialized, findings, categories_to_redact)
        try:
            return json.loads(redacted_serialized)
        except Exception:
            return redacted_serialized
    return data
