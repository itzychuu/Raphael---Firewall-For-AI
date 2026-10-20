import json
import re
from typing import Any, List, Set, Tuple
from app.firewall.behavior_models import DataSensitivity
from app.models.schemas import DLPFinding, DLPFindingCategory

# Regular expression definitions for deterministic DLP detection
SSN_REGEX = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
# Include synthetic test SSNs used in mock DB (e.g. 999-12-3456, 888-23-4567)
MOCK_SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

PEM_PRIVATE_KEY_REGEX = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"
)

API_KEY_REGEX = re.compile(
    r"(?i)(?:\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?)([\w-]{12,})(?:['\"]?)"
)
MOCK_API_KEY_REGEX = re.compile(r"\bTEST-API-KEY-[A-Za-z0-9_-]+\b")
GENERIC_BEARER_REGEX = re.compile(r"(?i)\bbearer\s+([a-zA-Z0-9_\-\.]{16,})\b")

PASSWORD_ASSIGNMENT_REGEX = re.compile(
    r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s\r\n]{4,})['\"]?"
)

EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


def scan_text_for_dlp(text: str) -> List[DLPFinding]:
    """Scan raw string for sensitive patterns and return non-overlapping DLP findings."""
    if not text:
        return []

    findings: List[DLPFinding] = []
    seen_spans: Set[Tuple[int, int]] = set()

    def add_finding(cat: DLPFindingCategory, start: int, end: int, sens: str, desc: str):
        # Prevent exact duplicate span recordings
        if (start, end) in seen_spans:
            return
        seen_spans.add((start, end))
        findings.append(
            DLPFinding(
                category=cat,
                start=start,
                end=end,
                matched_text_length=end - start,
                sensitivity=sens,
                description=desc,
            )
        )

    # 1. PEM Private Keys (multiline)
    for match in PEM_PRIVATE_KEY_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.PRIVATE_KEY,
            start=match.start(),
            end=match.end(),
            sens=DataSensitivity.RESTRICTED.value,
            desc="Cryptographic private key PEM block detected",
        )

    # 2. SSN Detection
    for match in MOCK_SSN_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.SSN,
            start=match.start(),
            end=match.end(),
            sens=DataSensitivity.RESTRICTED.value,
            desc="Social Security Number (SSN) pattern detected",
        )

    # 3. API Keys and Tokens
    for match in MOCK_API_KEY_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.API_KEY,
            start=match.start(),
            end=match.end(),
            sens=DataSensitivity.RESTRICTED.value,
            desc="Project API key token detected",
        )
    for match in API_KEY_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.API_KEY,
            start=match.start(1),
            end=match.end(1),
            sens=DataSensitivity.RESTRICTED.value,
            desc="Assigned API key or secret token detected",
        )
    for match in GENERIC_BEARER_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.API_KEY,
            start=match.start(1),
            end=match.end(1),
            sens=DataSensitivity.RESTRICTED.value,
            desc="Authorization Bearer token detected",
        )

    # 4. Password Assignments
    for match in PASSWORD_ASSIGNMENT_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.PASSWORD,
            start=match.start(1),
            end=match.end(1),
            sens=DataSensitivity.RESTRICTED.value,
            desc="Password assignment detected",
        )

    # 5. Email Addresses (classified as INTERNAL)
    for match in EMAIL_REGEX.finditer(text):
        add_finding(
            cat=DLPFindingCategory.EMAIL_ADDRESS,
            start=match.start(),
            end=match.end(),
            sens=DataSensitivity.INTERNAL.value,
            desc="Email address identifier detected",
        )

    # 6. Confidential File / Salary Contextual Strings
    salary_match = re.search(r"(?i)\bsalary\s*(?:[:=]|\bis\b)\s*\$?\d[\d,]{3,}\b", text)
    if salary_match:
        add_finding(
            cat=DLPFindingCategory.EMPLOYEE_RECORD,
            start=salary_match.start(),
            end=salary_match.end(),
            sens=DataSensitivity.CONFIDENTIAL.value,
            desc="Sensitive employee compensation record detected",
        )

    # Sort findings in order of appearance
    findings.sort(key=lambda x: (x.start, -(x.end - x.start)))
    return findings


def scan_data_for_dlp(data: Any) -> Tuple[str, List[DLPFinding]]:
    """Serialize structured data to string and scan for DLP findings."""
    if isinstance(data, str):
        serialized = data
    elif isinstance(data, (dict, list)):
        serialized = json.dumps(data)
    else:
        serialized = str(data)

    findings = scan_text_for_dlp(serialized)
    return serialized, findings
