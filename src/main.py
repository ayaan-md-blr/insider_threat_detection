import pandas as pd
from ingestion.load_data import load_data
from features.feature_engineering import *
from models.anamoly_detector import *
from rules.rule_engine import fire_rules

df = load_data(
    log_path=r"data/data_access_logs.csv",
    profile_path=r"data/user_profiles.csv")

df = build_features(df)
#print(list(df.columns))
#print(df[["hour", "is_weekend", "sensitivity_score", "action_score", "failed", "priv_score"]].head())
features = [
    "hour", 
    "action_score", 
    "sensitivity_score", 
    "failed", 
    "is_weekend", 
    "priv_score"
]

anamoly_df = detect_anomalies(df, features)

rules_df = fire_rules(anamoly_df)






