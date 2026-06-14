from risk_engine import SEVERITY_MAP


def evaluate_rule(rule, event):

    try:

        return eval(
            rule["condition"],
            {},
            event
        )

    except Exception:

        return False
    

def evaluate_event(event, rules):

    matched_rules = []

    risk_score = 0

    for rule in rules:

        if evaluate_rule(rule, event):

            matched_rules.append(
                rule["rule_id"]
            )

            risk_score += (
                SEVERITY_MAP[
                    rule["severity"]
                ]
            )

    return {
        "matched_rules": matched_rules,
        "risk_score": min(risk_score, 100)
    }