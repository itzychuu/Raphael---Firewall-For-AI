import re


INJECTION_PATTERNS = [

    r"ignore\s+(all\s+)?previous\s+instructions",

    r"ignore\s+your\s+instructions",

    r"ignore\s+the\s+system\s+prompt",

    r"reveal\s+(the\s+)?system\s+prompt",

    r"show\s+(me\s+)?your\s+system\s+prompt",

    r"reveal\s+(your\s+)?instructions",

    r"show\s+(me\s+)?your\s+instructions",

    r"developer\s+mode",

    r"system\s+override",

    r"bypass\s+(your\s+)?rules",

    r"disable\s+(your\s+)?safety",

    r"forget\s+(all\s+)?previous\s+instructions"
]


def detect_prompt_injection(text: str):

    matches = []

    for pattern in INJECTION_PATTERNS:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):

            matches.append(pattern)

    if matches:

        return {
            "detected": True,
            "risk": 90,
            "reason": "Potential prompt injection detected",
            "matches": matches
        }

    return {
        "detected": False,
        "risk": 0,
        "reason": None,
        "matches": []
    }