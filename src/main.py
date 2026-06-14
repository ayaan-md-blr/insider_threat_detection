import pandas as pd
from ingestion.load_data import load_data
from features.feature_engineering import *
from models.anamoly_detector import *
from rules.rule_engine import fire_rules

df = load_data(
    log_path=r"data/data_access_logs.csv",
    profile_path=r"data/user_profiles.csv")

print(df.head(), "hehehehhhhhhhhhhhhhhhhhhhhhhhhh")

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
anamoly_df = anamoly_df.sort_values(by="risk_score", ascending=False)

first_user_id = anamoly_df['user_id'].iloc[1]
print(first_user_id)
first_timestamp = anamoly_df['timestamp'].iloc[1]
print(first_timestamp, anamoly_df['risk_score'].iloc[1])

rules_df = fire_rules(anamoly_df)
rules_df['user_id'] = rules_df['user_id'].str.strip()
rules_df['timestamp'] = pd.to_datetime(rules_df['timestamp'], errors='coerce')

print(">>>>>>>>>>>>>", rules_df.head())

# Use the dynamic values instead of hardcoding
result3 = rules_df.query("user_id == 'USR00039' and timestamp == @first_timestamp")
print(result3)

print(anamoly_df.columns)
print(rules_df.columns)







