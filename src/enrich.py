import pandas as pd


def enrich_time_features(df):

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    df["access_hour"] = (
        df["timestamp"].dt.hour
    )

    df["is_weekend"] = (
        df["timestamp"].dt.dayofweek >= 5
    )

    return df

def enrich_first_time_access(df):

    df = df.sort_values(
        ["user_id", "timestamp"]
    )

    df["first_time_access"] = (
        ~df.duplicated(
            subset=["user_id", "resource"]
        )
    )

    return df

def row_to_event(row):

    return {

        "access_hour":
            row["access_hour"],

        "is_weekend":
            row["is_weekend"],

        "action":
            row["action"],

        "resource_sensitivity":
            row["resource_sensitivity"],

    }