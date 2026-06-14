"""
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
"""

"""
rule_engine.py — Core rule evaluation engine.

Responsibilities
----------------
1. Evaluate each rule's condition against an event dict.
2. Before firing an alert, check per-rule exceptions.
3. Apply global exceptions (inactive account → escalate severity).
4. Generate a human-readable explanation for every matched rule.
5. Return a structured result consumed by main.py.

Exception matching logic
------------------------
Each exception in a rule's "exceptions" list is a dict of field/value pairs
(plus an optional "reason" key).  An exception fires if *all* non-"reason"
fields in the dict match the corresponding field in the event.

Supported exception fields
  - Any event field (department, privilege_level, resource, action, …)
  - day_name  : "Monday" … "Sunday"  (computed in enrich.py)

Example
-------
  exceptions: [
    {"department": "Finance", "resource": "GL_System",
     "day_name": "Friday",
     "reason": "Finance performs end-of-week GL exports every Friday"}
  ]
"""

import pandas as pd
from typing import Any
import rules
from utils.helper import load_rules
from rules.enrich import enrich_time_features, enrich_first_time_access, row_to_event
from rules.risk_engine import compute_risk_score, get_risk_level


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce_systems_access(val: Any) -> list[str]:
    """Normalise systems_access to a list regardless of its source format."""
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        return [s.strip() for s in val.split("|") if s.strip()]
    return []


def _build_eval_context(event: dict, rule: dict) -> dict:
    """
    Extend the event dict with any rule-specific computed fields needed for
    safe condition evaluation.
    """
    ctx = {k: v for k, v in event.items()}

    # systems_access must be a list for the 'in' / 'not in' operator
    ctx["systems_access"] = _coerce_systems_access(event.get("systems_access", ""))

    # R005 needs resource_system_key resolved via the rule's lookup map
    if "resource_to_system_map" in rule:
        rmap = rule["resource_to_system_map"]
        ctx["resource_system_key"] = rmap.get(str(event.get("resource", "")), "UNKNOWN")

    return ctx


def _eval_condition(condition_str: str, ctx: dict) -> bool:
    """
    Safely evaluate a Python-like condition string with the event context.
    Uses a restricted __builtins__ to prevent arbitrary code execution.
    Returns False on any evaluation error.
    """
    try:
        return bool(eval(condition_str, {"__builtins__": {}}, ctx))  # noqa: S307
    except Exception:
        return False


def _values_match(event_val: Any, exc_val: Any) -> bool:
    """
    Compare an event field value against an exception field value.
    Handles list membership ('not in' style) and coerces types for safe
    string / bool comparison.
    """
    if isinstance(exc_val, list):
        return event_val in exc_val

    # Coerce booleans stored as strings ("true" / "false")
    if isinstance(event_val, bool):
        event_val = str(event_val).lower()
    if isinstance(exc_val, str) and exc_val.lower() in ("true", "false"):
        exc_val = exc_val.lower()
        if isinstance(event_val, str):
            event_val = event_val.lower()

    return event_val == exc_val


def _exception_matches(event: dict, exc: dict) -> bool:
    """
    Return True if every non-'reason' field in *exc* matches the event.
    All fields must match simultaneously (AND logic).
    """
    for field, value in exc.items():
        if field == "reason":
            continue
        if not _values_match(event.get(field), value):
            return False
    return True


def _check_exceptions(event: dict, rule: dict) -> tuple[bool, str]:
    """
    Iterate the rule's exceptions list.
    Return (True, reason) on the first match that suppresses the alert.
    Return (False, "") if no exception applies.
    """
    for exc in rule.get("exceptions", []):
        if _exception_matches(event, exc):
            return True, exc.get("reason", "Rule exception matched — alert suppressed")
    return False, ""


# ---------------------------------------------------------------------------
# Explanation templates
# ---------------------------------------------------------------------------

def _build_explanation(event: dict, rule: dict) -> str:
    """
    Return a one-line, analyst-friendly explanation of why this rule fired.
    Each template surfaces the key fields an investigator would want to see.
    """
    rid      = rule["rule_id"]
    name     = rule["name"]
    action   = event.get("action", "?")
    resource = event.get("resource", "?")
    username = event.get("username", "?")
    dept     = event.get("department", "?")
    priv     = event.get("privilege_level", "?")
    tc       = event.get("time_classification", "?")
    hour     = event.get("access_hour", "?")
    sens     = event.get("resource_sensitivity", "?")
    status   = event.get("status", "?")

    # Format hour safely
    try:
        hour_str = f"{int(hour):02d}:00"
    except (TypeError, ValueError):
        hour_str = str(hour)

    templates: dict[str, str] = {
        "R001": (
            f"After-hours {action} on '{resource}' (sensitivity={sens}) "
            f"at {hour_str} [{tc}] by {username} ({dept} / {priv})"
        ),
        "R002": (
            f"Bulk export_data on high-sensitivity '{resource}' "
            f"by {username} ({dept} / {priv})"
        ),
        "R003": (
            f"Non-privileged user '{username}' (privilege={priv}) "
            f"performed admin_operation on '{resource}'"
        ),
        "R004": (
            f"Service-account '{username}' performed interactive "
            f"action '{action}' on '{resource}'"
        ),
        "R005": (
            f"'{username}' accessed '{resource}' which is outside "
            f"their approved systems_access list"
        ),
        "R006": (
            f"Failed {action} on high-sensitivity '{resource}' by '{username}' "
            f"({dept}) — possible probing / brute-force attempt"
        ),
        "R007": (
            f"Admin_Console accessed by non-admin '{username}' "
            f"(privilege={priv}, dept={dept})"
        ),
        "R008": (
            f"SIEM accessed by '{username}' from out-of-scope "
            f"department '{dept}'"
        ),
        "R009": (
            f"PROD_DB accessed by '{username}' from non-technical "
            f"department '{dept}' — direct DB exposure risk"
        ),
        "R010": (
            f"HRIS (employee PII) accessed by '{username}' from "
            f"department '{dept}' — review required"
        ),
        "R011": (
            f"High-sensitivity '{resource}' accessed on weekend "
            f"at {hour_str} by {username} ({dept} / {priv})"
        ),
        "R012": (
            f"Customer_Vault export by '{username}' ({dept}) — "
            f"non-Sales / Marketing user exporting customer PII"
        ),
    }

    return templates.get(rid, f"[{rid}] {name}: {action} on '{resource}' by {username}")


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------

def evaluate_event(
    event: dict,
    rules: list[dict],
    global_exceptions: list[dict] | None = None,
) -> dict:
    """
    Evaluate an event against all rules.

    Returns
    -------
    dict with keys:
      matched_rules   : list[str]  — rule IDs that fired
      severities      : list[str]  — severity of each matched rule (after escalation)
      explanation     : str        — pipe-separated human-readable reasons
      suppressed      : list[dict] — rules that matched but were suppressed
    """
    matched_rules:  list[str]  = []
    severities:     list[str]  = []
    explanations:   list[str]  = []
    suppressed_rules: list[dict] = []

    is_inactive = not bool(event.get("is_active", True))

    for rule in rules:
        ctx = _build_eval_context(event, rule)

        # ── 1. Evaluate main condition ────────────────────────────────────
        if not _eval_condition(rule["condition"], ctx):
            continue

        # ── 2. Check per-rule exceptions ──────────────────────────────────
        suppressed, reason = _check_exceptions(event, rule)
        if suppressed:
            suppressed_rules.append({
                "rule_id":   rule["rule_id"],
                "rule_name": rule["name"],
                "reason":    reason,
            })
            continue

        # ── 3. Rule fires — determine effective severity ──────────────────
        severity = rule.get("severity", "medium")

        # Global exception: inactive account → escalate to critical
        if is_inactive and global_exceptions:
            for gexc in global_exceptions:
                if "is_active == false" in gexc.get("condition", ""):
                    severity = gexc.get("override_severity", severity)
                    break

        matched_rules.append(rule["rule_id"])
        severities.append(severity)
        explanations.append(_build_explanation(event, rule))

    return {
        "matched_rules":  matched_rules,
        "severities":     severities,
        "explanation":    " | ".join(explanations),
        "suppressed":     suppressed_rules,
    }



def fire_rules(df):

# ── Paths ──────────────────────────────────────────────────────────────────
    RULES_PATH   = r"src/rules/rules.json"
    ALERTS_PATH  = r"output/alerts.csv"

# ── 1. Load ────────────────────────────────────────────────────────────────
    rules, global_exceptions = load_rules(RULES_PATH)

    rule_lookup: dict[str, str] = {
        rule["rule_id"]: rule["name"] for rule in rules
    }

    # ── 3. Enrich ──────────────────────────────────────────────────────────────
    df = enrich_time_features(df)
    df = enrich_first_time_access(df)


    # ── 4. Evaluate ────────────────────────────────────────────────────────────
    alerts: list[dict] = []

    for _, row in df.iterrows():
        event  = row_to_event(row)
        result = evaluate_event(event, rules, global_exceptions)

        if not result["matched_rules"]:
            continue

        is_inactive = not bool(event.get("is_active", True))
        risk_score  = compute_risk_score(result["severities"], is_inactive)
        risk_level  = get_risk_level(risk_score)

        # ── Build suppressed-rule summary ──────────────────────────────────
        suppressed_summary = "; ".join(
            f"{s['rule_id']} ({s['reason']})"
            for s in result["suppressed"]
        ) if result["suppressed"] else ""

        alerts.append({
        # ── identity ──────────────────────────────────────────────────
            "user_id":              event["user_id"],
            "username":             event["username"],
            "email":                event["email"],
            "timestamp":            event["timestamp"],

            # ── user context ──────────────────────────────────────────────
            "department":           event["department"],
            "job_title":            event["job_title"],
            "privilege_level":      event["privilege_level"],
            "is_active":            event["is_active"],
            "days_inactive":        event["days_inactive"],

            # ── access details ────────────────────────────────────────────
            "action":               event["action"],
            "resource":             event["resource"],
            "resource_sensitivity": event["resource_sensitivity"],
            "status":               event["status"],
            "source_ip":            event["source_ip"],
            "time_classification":  event["time_classification"],
            "access_hour":          event["access_hour"],
            "day_name":             event["day_name"],
            "first_time_access":    event["first_time_access"],

            # ── rule engine output ────────────────────────────────────────
            "matched_rules":        ",".join(result["matched_rules"]),
            "rule_names":           ",".join(
                                    rule_lookup[r]
                                    for r in result["matched_rules"]
                                ),
            "risk_score":           risk_score,
            "risk_level":           risk_level,
            "explanation":          result["explanation"],
            "suppressed_rules":     suppressed_summary,
    })


    # ── 5. Write output ────────────────────────────────────────────────────────
    alerts_df = pd.DataFrame(alerts)
    alerts_df.to_csv(ALERTS_PATH, index=False)

    print(f"[done]  {len(alerts_df):,} alerts written → {ALERTS_PATH}")
    print(f"        Risk breakdown: "
      f"CRITICAL={len(alerts_df[alerts_df.risk_level == 'CRITICAL']):,}  "
      f"HIGH={len(alerts_df[alerts_df.risk_level == 'HIGH']):,}  "
      f"MEDIUM={len(alerts_df[alerts_df.risk_level == 'MEDIUM']):,}"
    )
    print(f"        Unique users flagged: {alerts_df['user_id'].nunique():,}")
    return alerts_df