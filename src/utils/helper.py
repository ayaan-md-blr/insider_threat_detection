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


 
def load_rules(path: str) -> tuple[list, list]:
    """
    Load rules.json and return (rules_list, global_exceptions_list).
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["rules"], data.get("global_exceptions", [])