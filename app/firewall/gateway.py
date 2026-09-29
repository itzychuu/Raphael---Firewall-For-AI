from app.firewall.input_firewall import (
    detect_prompt_injection
)

from app.firewall.policy import (
    make_decision
)


def inspect_input(user_input: str):

    analysis = detect_prompt_injection(
        user_input
    )

    decision = make_decision(
        analysis["risk"]
    )

    return {
        "risk": analysis["risk"],
        "decision": decision,
        "detected": analysis["detected"],
        "reason": analysis["reason"],
        "matches": analysis["matches"]
    }