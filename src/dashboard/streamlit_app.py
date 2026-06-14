import streamlit as st
import pandas as pd

df = pd.read_csv(
    r"outputs/scored_users.csv"
)

st.dataframe(
    df.sort_values(
        "risk_score",
        ascending=False
    )
)

import plotly.express as px

fig = px.histogram(
    df,
    x="risk_score"
)

st.plotly_chart(fig)

critical = df[
    df["risk_score"] > 80
]

st.dataframe(critical)