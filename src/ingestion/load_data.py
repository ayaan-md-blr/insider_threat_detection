import pandas as pd


def load_data(log_path, profile_path):

    logs = pd.read_csv(log_path)

    profiles = pd.read_csv(profile_path)

    df = logs.merge(
        profiles,
        on="user_id",
        how="left"
    )

    return df