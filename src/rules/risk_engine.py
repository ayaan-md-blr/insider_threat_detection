SEVERITY_MAP = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 90
}

def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    return "LOW"

