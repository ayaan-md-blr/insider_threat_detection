import pandas as pd
from ingestion.load_data import load_data
from features.feature_engineering import *
from models.anamoly_detector import *
from rules.rule_engine import fire_rules
from llm.report_generator import create_incident_report

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
anamoly_df = anamoly_df.sort_values(by="risk_score", ascending=False)
print(anamoly_df[["user_id", "risk_score"]].head(20))

###################################
rules_df = fire_rules(anamoly_df)
####################################
rules_df['user_id'] = rules_df['user_id'].str.strip()
rules_df['timestamp'] = pd.to_datetime(rules_df['timestamp'], errors='coerce')


columns = [
    'username_x', 
    'department', 'risk_score'
]

subset_df = anamoly_df.head(15)

# Ensure consistent types
subset_df['timestamp'] = pd.to_datetime(subset_df['timestamp'], errors='coerce')
rules_df['timestamp']   = pd.to_datetime(rules_df['timestamp'], errors='coerce')

subset_df['user_id'] = subset_df['user_id'].str.strip()
rules_df['user_id']   = rules_df['user_id'].str.strip()

# Define helper function to query rules_df
def get_explanation(uid, ts):
    match = rules_df.query("user_id == @uid and timestamp == @ts")
    if not match.empty:
        return match['explanation'].iloc[0]
    return None

def get_risk_level(uid, ts):
    match = rules_df.query("user_id == @uid and timestamp == @ts")
    if not match.empty:
        return match['risk_level'].iloc[0]
    return None

# Apply functions to each row of anamoly_df
subset_df['explanation'] = subset_df.apply(
    lambda row: get_explanation(row['user_id'], row['timestamp']), axis=1
)
subset_df['risk_level'] = subset_df.apply(
    lambda row: get_risk_level(row['user_id'], row['timestamp']), axis=1
)

# Pick the subset of columns you want
subset_cols = ['username_x', 'department', 'risk_score', 'explanation', 'risk_level']

#print(subset_df.head(25))

#create_incident_report(subset_df[subset_cols])

subset_df.to_csv(r"output/incident_data.csv", index=False)






