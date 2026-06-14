from sklearn.preprocessing import MinMaxScaler

def calculate_risk(df):

    scaler = MinMaxScaler()

    df["risk_score"] = (
        100 -
        scaler.fit_transform(
            df[["anomaly_score"]]
        ) * 100
    )

    return df