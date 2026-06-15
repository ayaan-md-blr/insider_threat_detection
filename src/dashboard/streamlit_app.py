"""
Insider Threat Detection Dashboard
Place this file at: insider_threat_detection/src/dashboard/streamlit_app.py
Run with:  streamlit run src/dashboard/streamlit_app.py
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os, sys, io, subprocess, tempfile, shutil

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Insider Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── base ── */
[data-testid="stAppViewContainer"] { background: #0d1117; }
[data-testid="stSidebar"]          { background: #161b22; border-right: 1px solid #30363d; }
[data-testid="stHeader"]           { background: transparent; }

/* ── typography ── */
h1, h2, h3 { color: #e6edf3 !important; letter-spacing: -0.02em; }
p, li       { color: #8b949e; }
label, .stSelectbox label { color: #8b949e !important; }

/* ── metric cards ── */
[data-testid="metric-container"] {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
}
[data-testid="metric-container"] > div > div:first-child { color: #8b949e !important; font-size: 0.78rem; text-transform: uppercase; letter-spacing: .08em; }
[data-testid="metric-container"] > div > div:last-child  { color: #e6edf3 !important; font-size: 2rem; font-weight: 700; }

/* ── tab strip ── */
.stTabs [data-baseweb="tab-list"] { background: #161b22; border-radius: 8px; gap: 4px; padding: 4px; border: 1px solid #30363d; }
.stTabs [data-baseweb="tab"]      { color: #8b949e; background: transparent; border-radius: 6px; padding: 6px 18px; font-size: 0.85rem; }
.stTabs [aria-selected="true"]    { background: #21262d !important; color: #e6edf3 !important; }

/* ── dataframe ── */
[data-testid="stDataFrame"] { border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }

/* ── file uploader ── */
[data-testid="stFileUploadDropzone"] {
    background: #161b22;
    border: 1px dashed #30363d;
    border-radius: 8px;
}
[data-testid="stFileUploadDropzone"]:hover { border-color: #58a6ff; }

/* ── buttons ── */
.stButton > button {
    background: #238636;
    color: #e6edf3;
    border: none;
    border-radius: 6px;
    font-weight: 600;
    padding: 8px 20px;
    width: 100%;
}
.stButton > button:hover { background: #2ea043; }

/* ── alert badges ── */
.badge-critical { background:#da3633; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; }
.badge-high     { background:#d29922; color:#000; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; }
.badge-medium   { background:#388bfd; color:#fff; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; }
.badge-low      { background:#3fb950; color:#000; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; }

/* ── section divider ── */
hr { border-color: #30363d; }

/* ── sidebar header ── */
.sidebar-logo { font-size:1.3rem; font-weight:700; color:#e6edf3; letter-spacing:-0.02em; margin-bottom:4px; }
.sidebar-sub  { font-size:0.78rem; color:#8b949e; margin-bottom:20px; }
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

RISK_COLORS = {
    "critical": "#da3633",
    "high":     "#d29922",
    "medium":   "#388bfd",
    "low":      "#3fb950",
}

def risk_color(score: float) -> str:
    if score >= 80: return RISK_COLORS["critical"]
    if score >= 60: return RISK_COLORS["high"]
    if score >= 40: return RISK_COLORS["medium"]
    return RISK_COLORS["low"]

def risk_label(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

def styled_df(df: pd.DataFrame) -> pd.io.formats.style.Styler:
    """Return a Styler with dark-mode-friendly row shading."""
    return df.style.set_properties(**{
        "background-color": "#161b22",
        "color": "#e6edf3",
        "border-color": "#30363d",
    })

def score_bar(df: pd.DataFrame, col: str = "risk_score") -> pd.io.formats.style.Styler:
    """Colour the risk_score column as a heat gradient."""
    def _color(val):
        c = risk_color(float(val))
        return f"color: {c}; font-weight: 700;"
    return styled_df(df).map(_color, subset=[col])

def load_csv(uploaded) -> pd.DataFrame | None:
    if uploaded is None:
        return None
    return pd.read_csv(uploaded)

def save_temp(uploaded, name: str, tmp_dir: str) -> str:
    path = os.path.join(tmp_dir, name)
    with open(path, "wb") as f:
        f.write(uploaded.getvalue())
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown('<div class="sidebar-logo">🛡️ Threat Lens</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-sub">Insider Threat Detection · v2.1</div>', unsafe_allow_html=True)
    st.markdown("---")

    # ── INPUT FILES ──────────────────────────────────────────────────────────
    st.markdown("**📂 Input Files**")
    log_file     = st.file_uploader("data_access_logs.csv",  type="csv", key="logs")
    profile_file = st.file_uploader("user_profiles.csv",     type="csv", key="profiles")

    st.markdown("---")

    # ── OUTPUT FILES ─────────────────────────────────────────────────────────
    st.markdown("**📊 Output Files** *(optional override)*")
    scored_file   = st.file_uploader("scored_users.csv",   type="csv", key="scored")
    alerts_file   = st.file_uploader("alerts.csv",         type="csv", key="alerts")
    incident_file = st.file_uploader("incident_data.csv",  type="csv", key="incident")

    st.markdown("---")

    # ── PROJECT ROOT ─────────────────────────────────────────────────────────
    st.markdown("**⚙️  Pipeline**")
    project_root = st.text_input(
        "Project root path",
        value=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
        help="Absolute path to insider_threat_detection/",
    )
    run_pipeline = st.button("▶  Run Pipeline", disabled=(log_file is None or profile_file is None))

    st.markdown("---")
    st.markdown("**🔎 Filters**")
    top_n       = st.slider("Top N high-risk rows", 10, 50, 20)
    min_score   = st.slider("Minimum risk score",   0,  100, 0)
    show_only   = st.multiselect("Show severity",   ["CRITICAL","HIGH","MEDIUM","LOW"],
                                 default=["CRITICAL","HIGH","MEDIUM","LOW"])


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

pipeline_output_dir = os.path.join(project_root, "output")
pipeline_ran = False

if run_pipeline and log_file and profile_file:
    with st.spinner("Running detection pipeline…"):
        tmp = tempfile.mkdtemp()
        try:
            # Write input files to temp dir mirroring project data/ folder
            data_dir = os.path.join(tmp, "data")
            os.makedirs(data_dir, exist_ok=True)
            save_temp(log_file,     "data_access_logs.csv", data_dir)
            save_temp(profile_file, "user_profiles.csv",    data_dir)

            main_py = os.path.join(project_root, "src", "main.py")
            result  = subprocess.run(
                [sys.executable, main_py],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                st.sidebar.success("✅ Pipeline finished")
                pipeline_ran = True
            else:
                st.sidebar.error("Pipeline error")
                with st.expander("🔴 Pipeline stderr"):
                    st.code(result.stderr)
        except Exception as exc:
            st.sidebar.error(f"Could not run pipeline: {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════════
# LOAD DATA  (uploaded overrides, then project output/, then demo)
# ═══════════════════════════════════════════════════════════════════════════════

def try_read(uploaded_file, fallback_path: str) -> pd.DataFrame | None:
    if uploaded_file is not None:
        return load_csv(uploaded_file)
    if os.path.exists(fallback_path):
        return pd.read_csv(fallback_path)
    return None

df_logs     = load_csv(log_file)
df_profiles = load_csv(profile_file)

df_scored   = try_read(scored_file,   os.path.join(pipeline_output_dir, "scored_users.csv"))
df_alerts   = try_read(alerts_file,   os.path.join(pipeline_output_dir, "alerts.csv"))
df_incident = try_read(incident_file, os.path.join(pipeline_output_dir, "incident_data.csv"))


# ═══════════════════════════════════════════════════════════════════════════════
# DETERMINE PRIMARY RISK TABLE  (scored_users > incident_data > alerts)
# ═══════════════════════════════════════════════════════════════════════════════

primary_df: pd.DataFrame | None = None
primary_source = ""

for candidate, label in [(df_scored, "scored_users"), (df_incident, "incident_data"), (df_alerts, "alerts")]:
    if candidate is not None and "risk_score" in candidate.columns:
        primary_df   = candidate.copy()
        primary_source = label
        break

if primary_df is not None:
    primary_df["risk_score"] = pd.to_numeric(primary_df["risk_score"], errors="coerce")
    primary_df["_severity"]  = primary_df["risk_score"].apply(risk_label)
    primary_df = primary_df[primary_df["risk_score"] >= min_score]
    primary_df = primary_df[primary_df["_severity"].isin(show_only)]
    top20 = primary_df.sort_values("risk_score", ascending=False).head(top_n)
else:
    top20 = None


# ═══════════════════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("## 🛡️ Insider Threat Detection Dashboard")
st.markdown(
    f"<p style='color:#8b949e;margin-top:-8px;'>Rule-based + anomaly scoring · "
    f"{'<span style=\"color:#3fb950\">●</span> Pipeline ready' if (not df_scored.empty or not df_alerts.empty or not df_incident.empty) else '<span style=\"color:#8b949e\">○ Upload output files or run the pipeline</span>'}"
    f"</p>",
    unsafe_allow_html=True,
)
st.markdown("---")


# ═══════════════════════════════════════════════════════════════════════════════
# KPI ROW
# ═══════════════════════════════════════════════════════════════════════════════

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

with kpi1:
    n_logs = len(df_logs) if df_logs is not None else (len(df_scored) if df_scored is not None else "—")
    st.metric("Log Events", f"{n_logs:,}" if isinstance(n_logs, int) else n_logs)

with kpi2:
    n_users = len(df_profiles) if df_profiles is not None else "—"
    st.metric("Users Profiled", f"{n_users:,}" if isinstance(n_users, int) else n_users)

with kpi3:
    n_alerts = len(df_alerts) if df_alerts is not None else "—"
    st.metric("Rule Alerts", f"{n_alerts:,}" if isinstance(n_alerts, int) else n_alerts)

with kpi4:
    if primary_df is not None:
        n_critical = (primary_df["_severity"] == "CRITICAL").sum()
        st.metric("Critical Events", f"{n_critical:,}")
    else:
        st.metric("Critical Events", "—")

with kpi5:
    if primary_df is not None and "risk_score" in primary_df.columns:
        avg_score = primary_df["risk_score"].mean()
        st.metric("Avg Risk Score", f"{avg_score:.1f}")
    else:
        st.metric("Avg Risk Score", "—")

st.markdown("---")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CONTENT TABS
# ═══════════════════════════════════════════════════════════════════════════════

tab_top, tab_scored, tab_alerts, tab_incident, tab_inputs = st.tabs([
    f"🔥 Top {top_n} High-Risk",
    "📋 Scored Users",
    "🚨 Alerts",
    "📄 Incident Data",
    "📂 Input Preview",
])


# ─── TAB 1 · TOP N HIGH-RISK ──────────────────────────────────────────────────
with tab_top:
    if top20 is None or top20.empty:
        st.info("Upload output files or run the pipeline to see high-risk actions here.")
    else:
        st.markdown(f"### Top {top_n} High-Risk Events  <span style='font-size:0.8rem;color:#8b949e;'>source: {primary_source}</span>",
                    unsafe_allow_html=True)

        # ── CHARTS ROW ──────────────────────────────────────────────────────
        ch1, ch2 = st.columns(2)

        with ch1:
            # Risk score distribution (top N only)
            fig_bar = px.bar(
                top20.sort_values("risk_score"),
                x="risk_score",
                y=top20.sort_values("risk_score").get(
                    "username_x", top20.sort_values("risk_score").get(
                        "username", top20.sort_values("risk_score").get("user_id", top20.index.astype(str))
                    )
                ),
                orientation="h",
                color="risk_score",
                color_continuous_scale=["#388bfd", "#d29922", "#da3633"],
                title="Risk Score per User",
                labels={"x": "Risk Score", "y": "User"},
            )
            fig_bar.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
                font_color="#8b949e", title_font_color="#e6edf3",
                coloraxis_showscale=False,
                margin=dict(l=0, r=10, t=36, b=0),
                height=340,
            )
            fig_bar.update_xaxes(gridcolor="#30363d", zerolinecolor="#30363d")
            fig_bar.update_yaxes(gridcolor="#30363d")
            st.plotly_chart(fig_bar, width='stretch')

        with ch2:
            # Severity breakdown donut
            sev_counts = top20["_severity"].value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            fig_pie = px.pie(
                sev_counts, names="severity", values="count",
                color="severity",
                color_discrete_map=RISK_COLORS,
                hole=0.55,
                title="Severity Breakdown",
            )
            fig_pie.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
                font_color="#8b949e", title_font_color="#e6edf3",
                legend=dict(font_color="#8b949e"),
                margin=dict(l=0, r=0, t=36, b=0),
                height=340,
            )
            st.plotly_chart(fig_pie, width='stretch')

        # ── TABLE ───────────────────────────────────────────────────────────
        st.markdown("#### Detailed Risk Table")

        # Pick the most useful display columns (adapt to whichever CSV is loaded)
        preferred = [
            "username_x", "username", "user_id",
            "department", "job_title", "action",
            "resource", "resource_sensitivity",
            "status", "timestamp",
            "risk_score", "_severity",
            "explanation", "risk_level",
        ]
        display_cols = [c for c in preferred if c in top20.columns]
        display_df   = top20[display_cols].rename(columns={"_severity": "severity"})

        # Colour the risk_score column
        def highlight_score(val):
            try:
                return f"color: {risk_color(float(val))}; font-weight: 700;"
            except Exception:
                return ""

        styled = (
            display_df.style
            .map(highlight_score, subset=["risk_score"])
            .set_properties(**{"background-color": "#161b22", "color": "#e6edf3", "border-color": "#30363d"})
            .set_table_styles([{
                "selector": "thead th",
                "props":    [("background-color","#21262d"), ("color","#e6edf3"),
                             ("text-transform","uppercase"), ("font-size","0.72rem"),
                             ("letter-spacing","0.06em")],
            }])
            .format({"risk_score": "{:.1f}"})
        )
        st.dataframe(styled, width='stretch', height=460)

        # ── DOWNLOAD ────────────────────────────────────────────────────────
        csv_bytes = display_df.to_csv(index=False).encode()
        st.download_button(
            f"⬇  Download top {top_n} CSV",
            data=csv_bytes,
            file_name=f"top_{top_n}_high_risk.csv",
            mime="text/csv",
        )


# ─── TAB 2 · SCORED USERS ─────────────────────────────────────────────────────
with tab_scored:
    if df_scored is None:
        st.info("No scored_users.csv found. Upload it in the sidebar or run the pipeline.")
    else:
        st.markdown(f"### Scored Users  <span style='color:#8b949e;font-size:0.85rem;'>{len(df_scored):,} rows</span>",
                    unsafe_allow_html=True)

        # Risk score histogram
        if "risk_score" in df_scored.columns:
            fig_hist = px.histogram(
                df_scored, x="risk_score", nbins=30,
                color_discrete_sequence=["#388bfd"],
                title="Risk Score Distribution",
            )
            fig_hist.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
                font_color="#8b949e", title_font_color="#e6edf3",
                bargap=0.05,
                margin=dict(l=0, r=0, t=36, b=0), height=280,
            )
            fig_hist.update_xaxes(gridcolor="#30363d")
            fig_hist.update_yaxes(gridcolor="#30363d")
            st.plotly_chart(fig_hist, width='stretch')

        sort_col = "risk_score" if "risk_score" in df_scored.columns else df_scored.columns[0]
        st.dataframe(
            df_scored.sort_values(sort_col, ascending=False),
            width='stretch', height=520,
        )


# ─── TAB 3 · ALERTS ───────────────────────────────────────────────────────────
with tab_alerts:
    if df_alerts is None:
        st.info("No alerts.csv found. Upload it in the sidebar or run the pipeline.")
    else:
        st.markdown(f"### Rule-Based Alerts  <span style='color:#8b949e;font-size:0.85rem;'>{len(df_alerts):,} alerts</span>",
                    unsafe_allow_html=True)

        # Rule breakdown
        if "rule_id" in df_alerts.columns or "rule_name" in df_alerts.columns:
            rule_col = "rule_name" if "rule_name" in df_alerts.columns else "rule_id"
            rule_counts = df_alerts[rule_col].value_counts().head(10).reset_index()
            rule_counts.columns = [rule_col, "count"]

            fig_rules = px.bar(
                rule_counts, x="count", y=rule_col, orientation="h",
                color="count", color_continuous_scale=["#388bfd","#d29922","#da3633"],
                title="Top Triggered Rules",
            )
            fig_rules.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
                font_color="#8b949e", title_font_color="#e6edf3",
                coloraxis_showscale=False,
                margin=dict(l=0, r=10, t=36, b=0), height=300,
            )
            fig_rules.update_xaxes(gridcolor="#30363d")
            fig_rules.update_yaxes(gridcolor="#30363d")
            st.plotly_chart(fig_rules, width='stretch')

        sort_col = "risk_score" if "risk_score" in df_alerts.columns else df_alerts.columns[0]
        st.dataframe(
            df_alerts.sort_values(sort_col, ascending=False),
            width='stretch', height=520,
        )


# ─── TAB 4 · INCIDENT DATA ────────────────────────────────────────────────────
with tab_incident:
    if df_incident is None:
        st.info("No incident_data.csv found. Upload it in the sidebar or run the pipeline.")
    else:
        st.markdown(f"### Incident Data  <span style='color:#8b949e;font-size:0.85rem;'>{len(df_incident):,} rows</span>",
                    unsafe_allow_html=True)

        # Department breakdown if available
        if "department" in df_incident.columns and "risk_score" in df_incident.columns:
            dept_df = (
                df_incident.groupby("department")["risk_score"]
                .agg(["mean","count"])
                .rename(columns={"mean":"avg_risk","count":"events"})
                .reset_index()
                .sort_values("avg_risk", ascending=False)
            )
            fig_dept = px.bar(
                dept_df, x="department", y="avg_risk",
                color="avg_risk", color_continuous_scale=["#388bfd","#d29922","#da3633"],
                title="Avg Risk Score by Department",
                text="events",
            )
            fig_dept.update_traces(texttemplate="%{text} events", textposition="outside")
            fig_dept.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
                font_color="#8b949e", title_font_color="#e6edf3",
                coloraxis_showscale=False,
                margin=dict(l=0, r=0, t=36, b=40), height=320,
            )
            fig_dept.update_xaxes(gridcolor="#30363d")
            fig_dept.update_yaxes(gridcolor="#30363d")
            st.plotly_chart(fig_dept, width='stretch')

        sort_col = "risk_score" if "risk_score" in df_incident.columns else df_incident.columns[0]
        st.dataframe(
            df_incident.sort_values(sort_col, ascending=False),
            width='stretch', height=480,
        )

        # Explanation viewer
        if "explanation" in df_incident.columns:
            st.markdown("#### Explanation Inspector")
            if "username_x" in df_incident.columns:
                user_opts = df_incident["username_x"].dropna().unique().tolist()
                sel_user  = st.selectbox("Select a user to inspect", user_opts)
                rows      = df_incident[df_incident["username_x"] == sel_user]
            else:
                rows = df_incident.head(20)

            for _, row in rows.iterrows():
                score = row.get("risk_score", 0)
                sev   = risk_label(score)
                color = risk_color(score)
                with st.expander(
                    f"{'🔴' if sev=='CRITICAL' else '🟡' if sev=='HIGH' else '🔵'} "
                    f"Score {score:.0f} · {sev}  —  {row.get('timestamp','')}"
                ):
                    st.markdown(
                        f"<span style='color:{color};font-weight:700;font-size:1.1rem;'>{score:.1f}</span>"
                        f" risk score",
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"**Explanation:** {row.get('explanation','—')}")
                    detail_cols = ["action","resource","resource_sensitivity","status","department","privilege_level"]
                    detail_cols = [c for c in detail_cols if c in row.index]
                    if detail_cols:
                        st.json({c: str(row[c]) for c in detail_cols})


# ─── TAB 5 · INPUT PREVIEW ────────────────────────────────────────────────────
with tab_inputs:
    st.markdown("### Input File Preview")

    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("#### data_access_logs.csv")
        if df_logs is not None:
            st.caption(f"{len(df_logs):,} rows · {len(df_logs.columns)} columns")
            st.dataframe(df_logs.head(50), width='stretch', height=420)
        else:
            st.info("Upload data_access_logs.csv in the sidebar.")

    with col_r:
        st.markdown("#### user_profiles.csv")
        if df_profiles is not None:
            st.caption(f"{len(df_profiles):,} rows · {len(df_profiles.columns)} columns")
            st.dataframe(df_profiles.head(50), width='stretch', height=420)
        else:
            st.info("Upload user_profiles.csv in the sidebar.")

    if df_logs is not None and df_profiles is not None:
        st.markdown("#### Column Reference")
        ref1, ref2 = st.columns(2)
        with ref1:
            st.code("\n".join(df_logs.columns.tolist()), language=None)
        with ref2:
            st.code("\n".join(df_profiles.columns.tolist()), language=None)