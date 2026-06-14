import json
import pandas as pd


def load_rules(path):

    with open(path, "r") as f:

        return json.load(f)["rules"]
    
def load_access_logs(path):

    return pd.read_csv(path)


def load_user_profiles(path):

    return pd.read_csv(path)