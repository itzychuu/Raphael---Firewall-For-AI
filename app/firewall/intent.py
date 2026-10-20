import re
from typing import Dict, List, Set, Tuple
from app.firewall.behavior_models import UserIntent

# Keyword mappings for deterministic baseline intent classification
INTENT_KEYWORDS: Dict[UserIntent, List[str]] = {
    UserIntent.CALCULATION: [
        "calculate", "computation", "compute", "sum", "multiply", "divide",
        "plus", "minus", "math", "arithmetic", "expression", "eval", "*", "+", "/", "-"
    ],
    UserIntent.PUBLIC_RESEARCH: [
        "search", "what is", "who is", "explain", "research", "tell me about",
        "find information", "lookup", "definition", "overview", "python", "fastapi", "llm"
    ],
    UserIntent.DATABASE_LOOKUP: [
        "employee", "staff", "salary", "ssn", "database", "record", "department",
        "worker", "payroll", "personnel", "employee_id"
    ],
    UserIntent.FILE_ACCESS: [
        "file", "read file", "report", "document", "instructions", "text file",
        "public_report", "confidential", "read"
    ],
    UserIntent.COMMUNICATION: [
        "email", "send email", "notify", "message", "contact", "dispatch",
        "send message", "mail", "recipient"
    ],
    UserIntent.GENERAL_INFORMATION: [
        "hello", "hi", "help", "who are you", "what can you do", "thanks", "thank you"
    ],
}

# Tools typically justified by intent
INTENT_TOOL_JUSTIFICATION: Dict[UserIntent, Set[str]] = {
    UserIntent.CALCULATION: {"calculator"},
    UserIntent.PUBLIC_RESEARCH: {"web_search"},
    UserIntent.DATABASE_LOOKUP: {"database_read"},
    UserIntent.FILE_ACCESS: {"file_read"},
    UserIntent.COMMUNICATION: {"send_email"},
    UserIntent.GENERAL_INFORMATION: {"web_search", "calculator"},
    UserIntent.UNKNOWN: set(),
}


def classify_intent(text: str) -> Tuple[UserIntent, float, str]:
    """Deterministically classify user request intent with an explicit confidence score.
    Returns (UserIntent, confidence, explanation).
    """
    if not text or not text.strip():
        return UserIntent.UNKNOWN, 0.0, "Empty user prompt"

    text_lower = text.lower()
    scores: Dict[UserIntent, int] = {intent: 0 for intent in INTENT_KEYWORDS}

    for intent, keywords in INTENT_KEYWORDS.items():
        for kw in keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                scores[intent] += 1
            elif kw in ["*", "+", "/", "-"] and kw in text_lower:
                # Direct arithmetic operator matches
                scores[intent] += 1

    # Determine highest scoring intent
    sorted_intents = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    best_intent, best_score = sorted_intents[0]

    if best_score == 0:
        return UserIntent.UNKNOWN, 0.2, "No specific intent keywords matched"

    total_matches = sum(scores.values())
    confidence = round(min(1.0, 0.5 + (best_score / (total_matches + 1)) * 0.5), 2)
    explanation = f"Matched {best_score} keywords associated with {best_intent.value}"

    return best_intent, confidence, explanation


def is_tool_justified_for_intent(tool_name: str, intent: UserIntent) -> bool:
    """Check if the requested tool is normally within the scope of the user's intent."""
    if intent == UserIntent.UNKNOWN:
        # For UNKNOWN intent, allow basic harmless tools, but not sensitive tools without justification
        return tool_name in {"calculator", "web_search", "file_read"}
    justified_tools = INTENT_TOOL_JUSTIFICATION.get(intent, set())
    return tool_name in justified_tools
