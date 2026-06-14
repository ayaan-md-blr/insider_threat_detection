from sklearn.ensemble import IsolationForest

from models.risk_scoring import calculate_risk
from utils.helper import generate_flags

class InsiderThreatModel:

    def __init__(self):

        self.model = IsolationForest(
            contamination=0.05,
            random_state=42
        )

    def fit(self, X):

        self.model.fit(X)

    def score(self, X):

        return self.model.decision_function(X)
    
def detect_anomalies(df, features):

    model = InsiderThreatModel()

    X = df[features]

    model.fit(X)

    df["anomaly_score"] = model.score(X)

    df = calculate_risk(df)
    """
    df["flags"] = df.apply(
        generate_flags,
        axis=1)
    """
    top_users = df.sort_values(by="risk_score", ascending=False).head(20)

    # Display the relevant columns
    print(top_users)

    df.to_csv(r"output/scored_users.csv", index=False)

    return df