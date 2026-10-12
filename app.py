import streamlit as st
import pandas as pd
import plotly.express as px
from ai_analyzer import analyze_alert

# -----------------------------
# Page Configuration
# -----------------------------
st.set_page_config(
    page_title="AI Powered Brute Force Detector",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# Global Styling (one theme for the whole page)
# -----------------------------
st.markdown("""
<style>
/* Page background */
.stApp {
    background-color: black;
}

/* Force readable text everywhere */
.stApp, .stApp p, .stApp span, .stApp label, .stApp li {
    color: #E5E7EB;
}

/* Page title and subtitle */
.page-title {
    font-size: 65px;
    font-weight: 800;
    color: white;
    margin-bottom: 0;
}
.page-subtitle {
    font-size: 35px;
    color: #9CA3AF;
    margin-top: 4px;
    margin-bottom: 24px;
}

/* Section headings */
.section-title {
    font-size: 50px;
    font-weight: 700;
    color: white;
    margin: 32px 0 16px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid White
    ;
}

/* Metric cards */
.metric-card {
    background-color: #111827;
    padding: 24px 16px;
    border-radius: 14px;
    text-align: center;
    border: 1px solid #374151;
}
.metric-title {
    font-size: 35px;
    font-weight: 600;
    color: #D1D5DB;
}
.metric-value {
    font-size: 50px;
    font-weight: 800;
    margin-top: 8px;
    line-height: 1.1;
}

/* Colours */
.red    { color: #F87171; }
.orange { color: #FB923C; }
.yellow { color: #FACC15; }
.blue   { color: #38BDF8; }

/* Summary table */
.soc-table {
    width: 100%;
    border-collapse: collapse;
    background-color: #111827;
    border-radius: 14px;
    overflow: hidden;
    font-size: 35px;
}
.soc-table th {
    background-color: #1F2937;
    color: white;
    text-align: left;
    padding: 16px 20px;
    border-bottom: 1px solid #374151;
}
.soc-table td {
    color: #E5E7EB;
    padding: 16px 20px;
    border-bottom: 1px solid #1F2937;
}
.soc-table tr:last-child td {
    border-bottom: none;
}

/* AI Investigation - adjustable typography */
.st-key-ai_investigation {
    --ai-section-heading-size: 50px;
    --ai-analysis-heading-size: 35px;
    --ai-body-size: 30px;
    --ai-control-size: 30px;
}

/* Main AI investigation heading */
.st-key-ai_investigation .section-title {
    font-size: var(--ai-section-heading-size) !important;
    color: #F0F2F7 !important;
    font-weight: 700 !important;
}

/* AI analysis subheading */
.st-key-ai_investigation .ai-analysis-title {
    font-size: var(--ai-analysis-heading-size) !important;
    color: #F0F2F7 !important;
    font-weight: 700 !important;
    margin: 20px 0 !important;
}

/* AI-generated paragraphs and lists */
.st-key-ai_investigation [data-testid="stMarkdownContainer"] p,
.st-key-ai_investigation [data-testid="stMarkdownContainer"] li {
    font-size: var(--ai-body-size) !important;
    line-height: 1.7 !important;
    color: #E0E5EE !important;
}

/* AI-generated subheadings */
.st-key-ai_investigation [data-testid="stMarkdownContainer"] h1,
.st-key-ai_investigation [data-testid="stMarkdownContainer"] h2,
.st-key-ai_investigation [data-testid="stMarkdownContainer"] h3 {
    font-size: var(--ai-analysis-heading-size) !important;
    color: #F0F2F7 !important;
}

/* Investigation button */
.st-key-ai_investigation .stButton button {
    font-size: var(--ai-control-size) !important;
    font-weight: 600 !important;
}
/* ===== Alert dropdown: change these two numbers ===== */
:root {
    --dropdown-font-size: 35px;   /* text size */
    --dropdown-box-height: 90px;  /* height of the closed box */
}

/* Label above the dropdown */
html body .stApp [data-testid="stSelectbox"] label p {
    font-size: var(--dropdown-font-size) !important;
    color: #E0E5EE !important;
}

/* The closed box */
html body .stApp [data-testid="stSelectbox"] [data-baseweb="select"] > div {
    min-height: var(--dropdown-box-height) !important;
    height: auto !important;
    align-items: center !important;
}

/* Everything inside the closed box (selected value, input) */
html body .stApp [data-testid="stSelectbox"] [data-baseweb="select"] * {
    font-size: var(--dropdown-font-size) !important;
    line-height: 1.4 !important;
    color: #E0E5EE !important;
    opacity: 1 !important;
}

/* Arrow icon */
html body .stApp [data-testid="stSelectbox"] [data-baseweb="select"] svg {
    width: calc(var(--dropdown-font-size) * 0.8) !important;
    height: calc(var(--dropdown-font-size) * 0.8) !important;
}

/* Open list of options */
html body [data-baseweb="popover"] [role="option"],
html body [data-baseweb="popover"] [role="option"] *,
html body [data-baseweb="popover"] li,
html body [data-baseweb="popover"] li * {
    font-size: var(--dropdown-font-size) !important;
    line-height: 1.4 !important;
    color: #E0E5EE !important;
}
html body [data-baseweb="popover"] [role="option"],
html body [data-baseweb="popover"] li {
    min-height: var(--dropdown-box-height) !important;
    display: flex !important;
    align-items: center !important;
}

</style>
""", unsafe_allow_html=True)

# -----------------------------
# Helper Functions
# -----------------------------
def metric_card(title, value, color):
    return f"""
    <div class="metric-card">
        <div class="metric-title">{title}</div>
        <div class="metric-value {color}">{value}</div>
    </div>
    """

def section(title):
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)

def assign_severity(attempts):
    if attempts >= 7:
        return "HIGH"
    elif attempts == 6:
        return "MEDIUM"
    else:
        return "LOW"

# -----------------------------
# Header
# -----------------------------
st.markdown('<div class="page-title">🛡️ AI Powered Brute Force Detector</div>', unsafe_allow_html=True)
st.markdown('<div class="page-subtitle">SOC Dashboard | Phase 1</div>', unsafe_allow_html=True)

# -----------------------------
# Load Dataset
# -----------------------------
logs = pd.read_csv("data/authentication_logs.csv")

failed_logins = logs[logs["login_status"] == "Failed"].copy()
alerts = failed_logins[failed_logins["failed_attempts"] >= 5].copy()
alerts["severity"] = alerts["failed_attempts"].apply(assign_severity)

# AI investigation feed for the selected alert workflow
alert_feed = alerts.copy()

# -----------------------------
# Metrics
# -----------------------------
total_alerts = len(alerts)
high_alerts = (alerts["severity"] == "HIGH").sum()
medium_alerts = (alerts["severity"] == "MEDIUM").sum()
low_alerts = (alerts["severity"] == "LOW").sum()

section("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.markdown(metric_card("🚨 Total Alerts", total_alerts, "blue"), unsafe_allow_html=True)
col2.markdown(metric_card("🔴 High Risk", high_alerts, "red"), unsafe_allow_html=True)
col3.markdown(metric_card("🟠 Medium Risk", medium_alerts, "orange"), unsafe_allow_html=True)
col4.markdown(metric_card("🟡 Low Risk", low_alerts, "yellow"), unsafe_allow_html=True)

# -----------------------------
# Threat Intelligence Summary
# -----------------------------
section("📊 Threat Intelligence Summary")

severity_summary = alerts["severity"].value_counts().reset_index()
severity_summary.columns = ["Severity Level", "Number of Alerts"]

table_html = severity_summary.to_html(index=False, classes="soc-table", border=0)
st.markdown(table_html, unsafe_allow_html=True)
# -----------------------------
# Failed Login Activity
# -----------------------------
section("📈 Failed Login Activity")

import plotly.express as px

failed_logins["timestamp"] = pd.to_datetime(
    failed_logins["timestamp"],
    errors="coerce"
)

hourly_failed_logins = (
    failed_logins
    .groupby(failed_logins["timestamp"].dt.hour)
    .size()
    .reset_index(name="Failed Login Events")
)

hourly_failed_logins.columns = [
    "Hour",
    "Failed Login Events"
]

hour_chart = px.bar(
    hourly_failed_logins,
    x="Hour",
    y="Failed Login Events",
    title="Failed Login Events by Hour",
    labels={
        "Hour": "Hour of Day",
        "Failed Login Events": "Failed Login Events"
    }
)
hour_chart.update_layout(
    title_font=dict(size=35, color="white"),
    font=dict(size=35, color="white"),
    xaxis=dict(
        title_font=dict(size=35, color="white"),
        tickfont=dict(size=30, color="white")
    ),
    yaxis=dict(
        title_font=dict(size=35, color="white"),
        tickfont=dict(size=30, color="white")
    )
)

# -----------------------------
# Match dashboard typography
# -----------------------------
hour_chart.update_layout(
    title={
        "text": "Failed Login Events by Hour",
        "font": {
            "size": 35,
            "color": "white"
        }
    },
    font={
        "size": 35,
        "color": "white"
    },
    xaxis={
        "title": {
            "text": "Hour of Day",
            "font": {
                "size": 35,
                "color": "white"
            }
        },
        "tickfont": {
            "size": 30,
            "color": "white"
        }
    },
    yaxis={
        "title": {
            "text": "Failed Login Events",
            "font": {
                "size": 35,
                "color": "white"
            }
        },
        "tickfont": {
            "size": 30,
            "color": "white"
        }
    },
    margin=dict(
        l=80,
        r=40,
        t=90,
        b=80
    ),
    height=550
)

st.plotly_chart(
    hour_chart,
    use_container_width=True
)
# -----------------------------
# Highest Cumulative Failed Attempts
# -----------------------------
section("🎯 Highest Cumulative Failed Attempts")

top_users = (
    failed_logins
    .groupby("user_id")["failed_attempts"]
    .sum()
    .reset_index()
)

top_users.columns = [
    "User ID",
    "Cumulative Failed Attempts"
]

top_users = (
    top_users
    .sort_values(
        by="Cumulative Failed Attempts",
        ascending=False
    )
    .head(10)
)

top_users_html = top_users.to_html(
    index=False,
    classes="soc-table",
    border=0
)

st.markdown(
    top_users_html,
    unsafe_allow_html=True
)
 
# -----------------------------
# SOC Analyst Observation
# -----------------------------
section("🔎 SOC Analyst Observation")

st.markdown("""
<div class="metric-card">
    <div class="metric-title">
       Authentication events with five or more failed attempts are
        flagged for further investigation. The severity level is based
        on the number of failed attempts recorded for each event. 
    </div>
</div>
""", unsafe_allow_html=True)
# -----------------------------
# Risk Level Distribution
# -----------------------------
section("📊 Risk Level Distribution")

risk_distribution = (
    alerts["severity"]
    .value_counts()
    .reset_index()
)

risk_distribution.columns = [
    "Risk Level",
    "Number of Alerts"
]

risk_chart = px.bar(
    risk_distribution,
    x="Risk Level",
    y="Number of Alerts",
    title="Risk Level Distribution",
    labels={
        "Risk Level": "Risk Level",
        "Number of Alerts": "Number of Alerts"
    }
)

risk_chart.update_layout(
    title={
        "text": "Risk Level Distribution",
        "font": {
            "size": 35,
            "color": "white"
        }
    },
    font={
        "size": 35,
        "color": "white"
    },
    xaxis={
        "title": {
            "text": "Risk Level",
            "font": {
                "size": 35,
                "color": "white"
            }
        },
        "tickfont": {
            "size": 30,
            "color": "white"
        }
    },
    yaxis={
        "title": {
            "text": "Number of Alerts",
            "font": {
                "size": 35,
                "color": "white"
            }
        },
        "tickfont": {
            "size": 30,
            "color": "white"
        }
    },
    margin=dict(
        l=80,
        r=40,
        t=90,
        b=80
    ),
    height=550
)

st.plotly_chart(
    risk_chart,
    use_container_width=True
)

# -----------------------------
# AI-Powered Alert Investigation
# -----------------------------
with st.container(key="ai_investigation"):

    section("🤖 AI Powered Alert Investigation")

    if not alert_feed.empty:
        selected_alert_id = st.selectbox(
            "Select an authentication alert",
            alert_feed["auth_event_id"].tolist(),
            key="alert_select"
        )

        if st.button("Analyze Selected Alert"):
            selected_alert = alert_feed[
                alert_feed["auth_event_id"] == selected_alert_id
            ].iloc[0]

            with st.spinner("Gemini is analyzing the alert..."):
                ai_result = analyze_alert(
                    selected_alert.to_dict()
                )

            st.markdown(
                '<div class="ai-analysis-title">'
                'AI Security Analysis'
                '</div>',
                unsafe_allow_html=True
            )

            st.markdown(ai_result)

    else:
        st.info("No alerts are available for AI analysis.")