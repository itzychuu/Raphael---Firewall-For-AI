def make_decision(risk: int):

    if risk <= 25:
        return "ALLOW"

    if risk <= 50:
        return "MONITOR"

    if risk <= 75:
        return "CONFIRM"

    return "BLOCK"