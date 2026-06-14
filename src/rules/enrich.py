"""
enrich.py — Feature engineering applied to the merged DataFrame before rule evaluation.
"""

import pandas as pd

# Day index → name mapping (Monday=0 … Sunday=6)
_DAY_NAMES = [
    "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday", "Sunday",
]


def enrich_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Parse timestamps and derive time-based features used by rules and exceptions.

    New columns
    -----------
    access_hour : int   — 0–23 hour of the access event
    is_weekend  : bool  — True for Saturday (5) or Sunday (6)
    day_of_week : int   — 0 = Monday … 6 = Sunday
    day_name    : str   — "Monday" … "Sunday"
    """
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["access_hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["day_name"]    = df["day_of_week"].map(lambda d: _DAY_NAMES[d])
    df["is_weekend"]  = df["day_of_week"] >= 5
    return df


def enrich_first_time_access(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flag the first time a user accesses each resource.

    New column
    ----------
    first_time_access : bool — True only on the earliest row per (user_id, resource) pair
    """
    df = df.sort_values(["user_id", "timestamp"])
    df["first_time_access"] = ~df.duplicated(subset=["user_id", "resource"])
    return df


def row_to_event(row) -> dict:
    """
    Convert a merged DataFrame row into an event dict for rule evaluation.

    Notes
    -----
    - username collides between logs and profiles after the merge:
        username_x  →  log value  (preferred)
        username_y  →  profile value
    - systems_access is kept as the raw pipe-separated string here;
      rule_engine._coerce_systems_access() splits it at evaluation time.
    """
    return {
        # ── time features (enrich_time_features) ──────────────────────────
        "access_hour":       row["hour"],
        "is_weekend":        row["is_weekend"],
        "day_of_week":       row["day_of_week"],
        "day_name":          row["day_name"],

        # ── first-access flag (enrich_first_time_access) ──────────────────
        "first_time_access": row["first_time_access"],

        # ── log fields ────────────────────────────────────────────────────
        "user_id":              row["user_id"],
        "username":             row["username_x"],
        "action":               row["action"],
        "resource":             row["resource"],
        "resource_sensitivity": row["resource_sensitivity"],
        "status":               row["status"],
        "source_ip":            row["source_ip"],
        "time_classification":  row["time_classification"],
        "timestamp":            str(row["timestamp"]),

        # ── profile fields (joined in main.py) ────────────────────────────
        "department":      row["department"],
        "job_title":       row["job_title"],
        "privilege_level": row["privilege_level"],
        "systems_access":  row["systems_access"],
        "email":           row["email"],
        "last_login":      row["last_login"],
        "days_inactive":   row["days_inactive"],
        "is_active":       row["is_active"],
        "hire_date":       row["hire_date"],
    }