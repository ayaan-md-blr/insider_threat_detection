from rules.risk_engine import SEVERITY_MAP, get_risk_level

from utils.helper import row_to_event, load_rules
import pandas as pd

rules = load_rules(
    r"src/rules/rules.json"
)

rule_lookup = {
    rule["rule_id"]: rule["name"]
    for rule in rules
}

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

def fire_rules(df):
    alerts = []

    for _, row in df.iterrows():

        event = row_to_event(row)

        #print(">>>>>>>>>>>>>>>>", event)

        result = evaluate_event(
            event,
            rules
        )

        if result["matched_rules"]:
            df["matched_rules"] = ",".join(result["matched_rules"])
            df["rule_risk_score"] = result["risk_score"]
            df["risk_level"] = get_risk_level(result["risk_score"])

            
    df.to_csv(
        "output/alerts.csv",
        index=False
    )
    return df