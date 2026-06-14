import pandas as pd

sensitivity_map = {
    "low":1,
    "medium":2,
    "high":3
}

action_map = {
    "login":1,
    "file_access":3,
    "sql_query":4,
    "export_data":5,
    "admin_operation":6,
    "api_call":2
}

priv_map = {
    "user":1,
    "service-account":2,
    "admin":3,
    "power-user":4
}



def build_features(df):

    df["timestamp"] = pd.to_datetime(
        df["timestamp"]
    )

    df["hour"] = df["timestamp"].dt.hour

    df["is_weekend"] = (
        df["timestamp"].dt.dayofweek >= 5
    ).astype(int)

    df["sensitivity_score"] = (
        df["resource_sensitivity"]
        .map(sensitivity_map)
    )

    df["action_score"] = (
        df["action"]
        .map(action_map)
    )

    df["failed"] = (
        df["status"] != "success"
    ).astype(int)

    df["priv_score"] = (
        df["privilege_level"]
        .map(priv_map)
    )

    return df

