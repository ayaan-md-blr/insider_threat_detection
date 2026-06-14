import pandas as pd
from risk_engine import get_risk_level

from loader import (
    load_rules,
    load_access_logs,
    load_user_profiles
)

from rule_engine import evaluate_event
from enrich import (
    enrich_time_features,
    enrich_first_time_access,
    row_to_event
)




rules = load_rules(
    r"rules/rules.json"
)

rule_lookup = {
    rule["rule_id"]: rule["name"]
    for rule in rules
}

"""
event = {

    "access_hour": 2,

    "data_sensitivity": "restricted",

    "rowcount": 50000,

    "destination": "external_email",

    "is_weekend": True,

    "first_time_access": True
}

result = evaluate_event(
    event,
    rules
)

print(result)
"""

logs_df = load_access_logs(
    r"data/data_access_logs.csv"
)

users_df = load_user_profiles(
    r"data/user_profiles.csv"
)

print(logs_df.columns.tolist())
print(users_df.columns.tolist())

df = logs_df.merge(
    users_df,
    on="user_id",
    how="left"
)

print(df.shape)

print(df.head())

df = enrich_time_features(df)

df = enrich_first_time_access(df)

alerts = []

for _, row in df.iterrows():

    event = row_to_event(row)

    #print(">>>>>>>>>>>>>>>>", event)

    result = evaluate_event(
        event,
        rules
    )

    if result["matched_rules"]:

        alerts.append({

            "user_id":
                row["user_id"],

            "timestamp":
                row["timestamp"],

            "matched_rules":
                ",".join(
                    result["matched_rules"]
                ),

            "rule_names":
            [
                rule_lookup[r]
                for r in result["matched_rules"]
            ],

            "risk_score":
                result["risk_score"],

            "risk_level": get_risk_level(result["risk_score"])
        })

alerts_df = pd.DataFrame(alerts)
print(alerts_df.head())
alerts_df.to_csv(
    "output/alerts.csv",
    index=False
)