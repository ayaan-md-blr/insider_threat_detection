import json

def generate_flags(row):

    flags = []

    if row["hour"] < 6:
        flags.append("Access during unusual hours")

    if row["sensitivity_score"] > 2:
        flags.append("Sensitive data accessed")

    #if row["access_count"] > 20:
    #    flags.append("Large data volume")

    return ",".join(flags)


def row_to_event(row):

    return {

        "hour":
            row["hour"],

        "is_weekend":
            row["is_weekend"],

        "action":
            row["action"],

        "resource_sensitivity":
            row["resource_sensitivity"],

    }

def load_rules(path):

    with open(path, "r") as f:

        return json.load(f)["rules"]