import pandas as pd
import plotly.express as px
import json 
from alert_detection import detect_alerts
from ai_investigation import is_successful_analysis
from investigation_history import add_investigation_history
from severity import assign_severity
from ai_analyzer import analyze_alert
import uuid
from datetime import datetime
import streamlit as st
from database import (
    get_all_statuses,
    save_status,
    get_audit_history,
)
if "ai_investigation_history" not in st.session_state:
    st.session_state.ai_investigation_history = []
# -----------------------------
# Page Configuration
# -----------------------------
st.set_page_config(
    page_title="AI Powered Brute Force Detector",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# Chart Customization Controls
# -----------------------------
with st.sidebar:
    st.title("📊 Graph Settings")

    CHART_HEIGHT = st.slider(
        "Graph height (px)",
        min_value=250,
        max_value=900,
        value=450,
        step=50
    )


    CHART_WIDTH = st.slider(
        "Graph width (%)",
        min_value=50,
        max_value=100,
        value=100,
        step=10
    )

    

    CHART_TITLE_SIZE = st.slider(
        "Graph title font size",
        min_value=12,
        max_value=40,
        value=25,
        step=1
    )

    CHART_TICK_SIZE = st.slider(
        "Axis font size",
        min_value=8,
        max_value=30,
        value=16,
        step=1
    )



# -----------------------------
# Global Styling
# -----------------------------
st.markdown("""
<style>
/* ===== CHANGE SIZES HERE ===== */
:root {
    --page-title-size: 65px;
    --subtitle-size: 35px;
    --section-size: 50px;
    --card-title-size: 35px;
    --card-value-size: 50px;
    --card-height: 260px;      /* how tall the boxes are */
    --card-padding: 40px 20px; /* space inside the boxes */
    --info-size: 30px;         /* text in the observation box */
    --table-size: 35px;
}
.alert-filter-caption {
    font-size: 20px !important;
    line-height: 1.5 !important;
    color: #E5E7EB !important;
    margin: 12px 0 !important;
}
/* Page background and default text */
.stApp {
    background-color: black;
}
.stApp, .stApp p, .stApp span, .stApp label, .stApp li {
    color: #E5E7EB;
}

/* Page title and subtitle */
.page-title {
    font-size: var(--page-title-size);
    font-weight: 800;
    color: white;
    margin-bottom: 0;
}
.page-subtitle {
    font-size: var(--subtitle-size);
    color: #9CA3AF;
    margin-top: 4px;
    margin-bottom: 24px;
}

/* Section headings */
.section-title {
    font-size: var(--section-size);
    font-weight: 700;
    color: white;
    margin: 32px 0 16px 0;
    padding-bottom: 8px;
    border-bottom: 1px solid white;
}

/* Metric cards (the boxes) */
.metric-card {
    background-color: #111827;
    padding: var(--card-padding);
    min-height: var(--card-height);
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    border-radius: 14px;
    text-align: center;
    border: 1px solid #374151;
}
.metric-title {
    font-size: var(--card-title-size);
    font-weight: 600;
    color: #D1D5DB;
}
.metric-value {
    font-size: var(--card-value-size);
    font-weight: 800;
    margin-top: 12px;
    line-height: 1.1;
}

/* Wide text box (SOC Analyst Observation) */
.info-card {
    background-color: #111827;
    padding: 30px 40px;
    border-radius: 14px;
    border: 1px solid #374151;
    font-size: var(--info-size);
    line-height: 1.7;
    color: #E5E7EB;
}

/* Colours */
.red    { color: #F87171; }
.orange { color: #FB923C; }
.yellow { color: #FACC15; }
.blue   { color: #38BDF8; }

/* Tables */
.soc-table {
    width: 100%;
    border-collapse: collapse;
    background-color: #111827;
    border-radius: 14px;
    overflow: hidden;
    font-size: var(--table-size);
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
/* Alert Queue: use the same typography as dashboard tables */
.alert-queue-scroll {
    width: 100%;
    max-height: 800px;
    overflow-y: auto;
    overflow-x: auto;
    border-radius: 14px;
}

.alert-queue-scroll .soc-table {
    width: 100%;
    font-size: var(--table-size);
}

.alert-queue-scroll .soc-table th,
.alert-queue-scroll .soc-table td {
    font-size: var(--table-size);
    padding: 16px 20px;
}

/* Colour-code alert severity in the Alert Queue */
.alert-queue-scroll .soc-table td:nth-child(5) {
    font-weight: 700;
}

.alert-queue-scroll .soc-table td:nth-child(5) {
    white-space: nowrap;
}

/* ===== AI Investigation section ===== */
.st-key-ai_investigation {
    --ai-section-heading-size: 50px;
    --ai-analysis-heading-size: 35px;
    --ai-body-size: 30px;
    --ai-control-size: 30px;
}
.st-key-ai_investigation .section-title {
    font-size: var(--ai-section-heading-size) !important;
    color: #F0F2F7 !important;
    font-weight: 700 !important;
}
.st-key-ai_investigation .ai-analysis-title {
    font-size: var(--ai-analysis-heading-size) !important;
    color: #F0F2F7 !important;
    font-weight: 700 !important;
    margin: 20px 0 !important;
}
.st-key-ai_investigation [data-testid="stMarkdownContainer"] p,
.st-key-ai_investigation [data-testid="stMarkdownContainer"] li {
    font-size: var(--ai-body-size) !important;
    line-height: 1.7 !important;
    color: #E0E5EE !important;
}
.st-key-ai_investigation [data-testid="stMarkdownContainer"] h1,
.st-key-ai_investigation [data-testid="stMarkdownContainer"] h2,
.st-key-ai_investigation [data-testid="stMarkdownContainer"] h3 {
    font-size: var(--ai-analysis-heading-size) !important;
    color: #F0F2F7 !important;
}

/* Analyze button (Red box, white text so it is always visible) */
.st-key-ai_investigation .stButton button {
    background-color: #EF4444 !important;
    border: 1px solid #374151 !important;
    padding: 15px 32px !important;
}
.st-key-ai_investigation .stButton button p {
    font-size: var(--ai-control-size) !important;
    font-weight: 600 !important;
    color: white !important;
}
/* ===== Responsive AI alert dropdown ===== */
:root {
    --dropdown-font-size: 30px;
    --dropdown-min-height: 90px;
}

/* Label above the dropdown */
.st-key-ai_investigation [data-testid="stSelectbox"] label,
.st-key-ai_investigation [data-testid="stSelectbox"] label p {
    font-size: var(--dropdown-font-size) !important;
    color: #E0E5EE !important;
}

/* Dropdown control: minimum height, not a fixed height */
.st-key-ai_investigation [data-testid="stSelectbox"] [data-baseweb="select"] > div {
    min-height: var(--dropdown-min-height) !important;
    height: auto !important;
    box-sizing: border-box !important;
    background-color: blue !important;
    border: 1px solid green !important;
    padding: 12px 14px !important;
}

/* Selected alert text and internal dropdown text */
.st-key-ai_investigation [data-testid="stSelectbox"] [data-baseweb="select"] * {
    font-size: var(--dropdown-font-size) !important;
    line-height: 1.4 !important;
    color: #E0E5EE !important;
    opacity: 1 !important;
}

/* Dropdown arrow */
.st-key-ai_investigation [data-testid="stSelectbox"] [data-baseweb="select"] svg {
    width: 22px !important;
    height: 25px !important;
}


/* Options menu */
[data-baseweb="popover"] [role="listbox"],
[role="listbox"] {
    background-color: #111827 !important;
}

/* Make dropdown option text larger and readable */
[role="option"],
[role="option"] * {
    font-size: 30px !important;
    line-height: 1.5 !important;
    color: yellow !important;
    opacity: 1 !important;
}

/* Give each option enough space */
[role="option"] {
    min-height: 56px !important;
    height: auto !important;
    padding: 16px 18px !important;
    box-sizing: border-box !important;
}
/* Fix the actual selected-value input */
.st-key-ai_investigation input[role="combobox"] {
    font-size: var(--dropdown-font-size) !important;
    line-height: 1.4 !important;
    color: yellow !important;
    background-color: #111827 !important;
    min-height: var(--dropdown-min-height) !important;
    height: auto !important;
    padding: 12px 14px !important;
    box-sizing: border-box !important;
    width: 100% !important;
}

/* Keep the input readable when focused */
.st-key-ai_investigation input[role="combobox"]:focus {
    font-size: var(--dropdown-font-size) !important;
    color: yellow !important;
}

/* ===== Advanced Alert Management ===== */
.stApp [data-testid="stMarkdownContainer"] h3 {
    font-size: 35px !important;
    line-height: 1.4 !important;
}

.stApp label,
.stApp label p,
.stApp input,
.stApp [data-baseweb="select"] *,
.stApp button,
.stApp button p {
    font-size: 30px !important;
    line-height: 1.5 !important;
}

.stApp [data-testid="stMetricLabel"],
.stApp [data-testid="stMetricLabel"] *,
.stApp [data-testid="stMetricValue"] {
    font-size: 30px !important;
    line-height: 1.5 !important;
}

.stApp [data-testid="stDataFrame"] {
    width: 100% !important;
}

/* Make Alert Management captions readable */
.st-key-advanced_alert_management
[data-testid="stCaptionContainer"],
.st-key-advanced_alert_management
[data-testid="stCaptionContainer"] p {
    font-size: 24px !important;
    line-height: 1.5 !important;
    color: #E5E7EB !important;
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

def info_card(text):
    return f'<div class="info-card">{text}</div>'
def style_alert_row(row):
    severity = row.get("Severity", "LOW")

    if severity == "HIGH":
        background = "#B30E0E"
        text_color = "#FEE2E2"
    elif severity == "MEDIUM":
        background = "#FA5C00"
        text_color = "#FEF3C7"
    else:
        background = "#713F12"
        text_color = "#FEF9C3"

    return [
        f"background-color: {background}; color: {text_color};"
        for _ in row
    ]
def section(title):
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)

#def assign_severity(attempts):
    #if attempts >= 7:
       # return "HIGH"
    #elif attempts == 6:
       # return "MEDIUM"
    #else:
        #return "LOW"


def style_chart(fig, title, x_title, y_title):
    """Apply dashboard styling and adjustable chart settings."""
    white = "white"

    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        title={
            "text": title,
            "font": {
                "size": CHART_TITLE_SIZE,
                "color": white
            }
        },
        font={
            "size": CHART_TICK_SIZE,
            "color": white
        },
        xaxis={
            "title": {
                "text": x_title,
                "font": {
                    "size": CHART_TITLE_SIZE,
                    "color": white
                }
            },
            "tickfont": {
                "size": CHART_TICK_SIZE,
                "color": white
            }
        },
        yaxis={
            "title": {
                "text": y_title,
                "font": {
                    "size": CHART_TITLE_SIZE,
                    "color": white
                }
            },
            "tickfont": {
                "size": CHART_TICK_SIZE,
                "color": white
            }
        },
        xaxis_showline=True,
yaxis_showline=True,
xaxis_linecolor="white",
yaxis_linecolor="white",
xaxis_linewidth=1,
yaxis_linewidth=1,
        margin=dict(l=80, r=40, t=90, b=80),
        height=CHART_HEIGHT,
        showlegend=False
    )

    return fig


# -----------------------------
# Header
# -----------------------------
st.markdown('<div class="page-title">🛡️ AI Powered Brute Force Detector</div>', unsafe_allow_html=True)
st.markdown('<div class="page-subtitle">SOC Dashboard | Phase 1</div>', unsafe_allow_html=True)

# -----------------------------
# Load Dataset
# -----------------------------
logs = pd.read_csv("data/authentication_logs.csv")

alerts = detect_alerts(logs)
failed_logins = logs[logs["failed_attempts"] > 0].copy()

alert_feed = alerts.copy()
# -----------------------------
# Alert Management Session State
# -----------------------------
if "alert_statuses" not in st.session_state:
    st.session_state.alert_statuses = get_all_statuses()
# -----------------------------
# Security Overview
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

# =========================
# Alert Severity Summary
# =========================

section("🚦 Alert Severity Summary")

severity_counts = (
    alerts["severity"]
    .value_counts()
    .reindex(["HIGH", "MEDIUM", "LOW"], fill_value=0)
)

total_alerts = int(severity_counts.sum())

if total_alerts == 0:
    st.info("No alerts available for severity analysis.")
else:
    severity_cols = st.columns(3)

    for col, severity in zip(
        severity_cols, ["HIGH", "MEDIUM", "LOW"]
    ):
        count = int(severity_counts[severity])
        percentage = (count / total_alerts) * 100

        with col:
            st.metric(
                f"{severity} Severity",
                count,
                f"{percentage:.1f}% of alerts",
            )

# -----------------------------
# Threat Intelligence Summary
# -----------------------------
section("📊 Threat Intelligence Summary")

severity_summary = alerts["severity"].value_counts().reset_index()
severity_summary.columns = ["Severity Level", "Number of Alerts"]

st.markdown(
    severity_summary.to_html(index=False, classes="soc-table", border=0),
    unsafe_allow_html=True
)
# -----------------------------
# Failed Attempt Distribution Chart
# -----------------------------
section("📈 Failed Attempt Distribution")
failed_attempt_distribution = (
    failed_logins["failed_attempts"]
    .value_counts()
    .sort_index()
    .rename_axis("Failed Attempts")
    .reset_index(name="Number of Records")
)
#st.subheader("Failed Attempt Distribution")

attempt_chart = px.bar(
    failed_attempt_distribution,
    x="Failed Attempts",
    y="Number of Records"
)
attempt_chart = style_chart(
    attempt_chart,
    "Failed Attempt Distribution",
    "Number of Failed Attempts",
    "Number of Records"
)
if CHART_WIDTH == 100:
    chart_area = st.container()
else:
    side_ratio = (100 - CHART_WIDTH) / 2
    left_space, chart_area, right_space = st.columns(
        [side_ratio, CHART_WIDTH, side_ratio]
    )

with chart_area:
    st.plotly_chart(
        attempt_chart,
        use_container_width=True,
        theme=None
    )

# -----------------------------
# Failed Login Activity
# -----------------------------
section("📈 Failed Login Activity")

failed_logins["timestamp"] = pd.to_datetime(failed_logins["timestamp"], errors="coerce")

hourly_failed_logins = (
    failed_logins
    .groupby(failed_logins["timestamp"].dt.hour)
    .size()
    .reset_index()
)
hourly_failed_logins.columns = ["Hour", "Failed Login Events"]

hour_chart = px.bar(hourly_failed_logins, x="Hour", y="Failed Login Events")
hour_chart = style_chart(
    hour_chart,
    "Failed Login Events by Hour",
    "Hour of Day",
    "Failed Login Events"
)
hour_chart.update_xaxes(dtick=1)

# Display chart at the selected width

if CHART_WIDTH == 100:
    chart_area = st.container()
else:
    left_ratio = (100 - CHART_WIDTH) / 2
    left_space, chart_area, right_space = st.columns(
        [left_ratio, CHART_WIDTH, left_ratio]
    )

with chart_area:
    st.plotly_chart(
        hour_chart,
        use_container_width=True,
        theme=None
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
top_users.columns = ["User ID", "Cumulative Failed Attempts"]
top_users = top_users.sort_values("Cumulative Failed Attempts", ascending=False).head(10)

st.markdown(
    top_users.to_html(index=False, classes="soc-table", border=0),
    unsafe_allow_html=True
)

# -----------------------------
# SOC Analyst Observation
# -----------------------------
section("🔎 SOC Analyst Observation")

st.markdown(
    info_card(
        "Authentication events with five or more failed attempts are "
        "flagged for further investigation. The severity level is based "
        "on the number of failed attempts recorded for each event."
    ),
    unsafe_allow_html=True
)

# -----------------------------
# Advanced Alert Management
# -----------------------------
with st.container(key="advanced_alert_management"):
    section("🛡️ Advanced Alert Management")


if alert_feed.empty:
    st.info("No alerts are available for management.")

else:
    # Search and filtering controls
    st.markdown("### Search and Filter Alerts")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        alert_search = st.text_input(
            "Search by Alert ID or User ID",
            placeholder="Enter an alert ID or user ID...",
            key="alert_management_search"
        )

    with filter_col2:
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=["HIGH", "MEDIUM", "LOW"],
            default=["HIGH", "MEDIUM", "LOW"],
            key="alert_management_severity"
        )

    status_filter = st.multiselect(
        "Filter by Investigation Status",
        options=[
            "New",
            "In Progress",
            "Escalated",
            "Closed"
        ],
        default=[
            "New",
            "In Progress",
            "Escalated",
            "Closed"
        ],
        key="alert_management_status_filter"
    )

    # Create a separate view so the original alert data is unchanged
    managed_alerts = alert_feed.copy()

    managed_alerts["investigation_status"] = (
        managed_alerts["auth_event_id"]
        .astype(str)
        .map(st.session_state.alert_statuses)
        .fillna("New")
    )

# Apply severity filter
managed_alerts = managed_alerts[
    managed_alerts["severity"].isin(severity_filter)
]
# Display the selected severity filter
st.markdown(
    f"""
    <div class="alert-filter-caption">
        Severity filter selected: {', '.join(severity_filter) if severity_filter else 'None'}
    </div>
    """,
    unsafe_allow_html=True
)

if not managed_alerts.empty:
    st.markdown(
        f"""
        <div class="alert-filter-caption">
            Severities in matching alerts: {', '.join(sorted(managed_alerts['severity'].unique()))}
        </div>
        """,
        unsafe_allow_html=True
    )

    # Apply status filter
    managed_alerts = managed_alerts[
        managed_alerts["investigation_status"].isin(status_filter)
    ]

    # Search alert IDs and user IDs
    if alert_search.strip():
        search_term = alert_search.strip().lower()

        matches = (
            managed_alerts["auth_event_id"]
            .astype(str)
            .str.lower()
            .str.contains(search_term, na=False)
            |
            managed_alerts["user_id"]
            .astype(str)
            .str.lower()
            .str.contains(search_term, na=False)
        )

        managed_alerts = managed_alerts[matches]

    # Sort alerts by severity and failed attempts
    severity_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    managed_alerts["severity_rank"] = (
        managed_alerts["severity"].map(severity_order).fillna(0)
    )

    managed_alerts = managed_alerts.sort_values(
        by=["severity_rank", "failed_attempts"],
        ascending=[False, False]
    )

    # Summary metrics for the filtered results
    metric1, metric2, metric3 = st.columns(3)
    st.divider()
    metric1.metric("Matching Alerts", len(managed_alerts))
    metric2.metric(
        "High-Risk Alerts",
        int((managed_alerts["severity"] == "HIGH").sum())
    )
    metric3.metric(
        "Open Investigations",
        int(
            managed_alerts["investigation_status"]
            .isin(["New", "In Progress", "Escalated"])
            .sum()
        )
    )

    # Display the highest-priority matching alerts
    st.markdown("### Alert Queue")

    display_columns = [
        "auth_event_id",
        "user_id",
        "login_status",
        "failed_attempts",
        "severity",
        "investigation_status"
    ]

    st.markdown(
    '<div class="alert-filter-caption">'
    'Showing the first 100 matching alerts, ordered by severity '
    'and failed attempts.'
    '</div>',
    unsafe_allow_html=True
)

    alert_queue_display = (
        managed_alerts[display_columns]
        .head(100)
        .rename(columns={
            "auth_event_id": "Alert ID",
            "user_id": "User ID",
            "login_status": "Login Status",
            "failed_attempts": "Failed Attempts",
            "severity": "Severity",
            "investigation_status": "Investigation Status"
        })
    )

    styled_alert_queue = (
        alert_queue_display.style
        .apply(style_alert_row, axis=1)
        .format(escape="html")
    )

    st.markdown(
        '<div class="alert-queue-scroll">'
        + styled_alert_queue.to_html(
            index=False,
            table_attributes='class="soc-table"'
        )
        + '</div>',
        unsafe_allow_html=True
    )

    # Update an individual alert's investigation status
    st.markdown("### Update Investigation Status")

    if not managed_alerts.empty:
        selected_management_alert = st.selectbox(
            "Select an alert to update",
            options=managed_alerts["auth_event_id"].tolist(),
            format_func=lambda alert_id: (
                f"{alert_id} | "
                f"{managed_alerts.loc[managed_alerts['auth_event_id'] == alert_id, 'severity'].iloc[0]} | "
                f"User: "
                f"{managed_alerts.loc[managed_alerts['auth_event_id'] == alert_id, 'user_id'].iloc[0]}"
            ),
            key="management_selected_alert"
        )

        selected_management_row = managed_alerts[
            managed_alerts["auth_event_id"] == selected_management_alert
        ].iloc[0]

        current_status = st.session_state.alert_statuses.get(
            str(selected_management_alert),
            "New"
        )

        new_status = st.selectbox(
            "New Investigation Status",
            options=[
                "New",
                "In Progress",
                "Escalated",
                "Closed"
            ],
            index=[
                "New",
                "In Progress",
                "Escalated",
                "Closed"
            ].index(current_status),
            key=f"management_status_{selected_management_alert}"
        )

        st.write(
    f"Selected alert severity: **{selected_management_row['severity']}**"
        )

        if st.button(
            "Save Investigation Status",
            key="save_alert_management_status"
        ):
            save_status(
                str(selected_management_alert),
                new_status
            )

            st.session_state.alert_statuses[
                str(selected_management_alert)
            ] = new_status

            st.success(
                f"Alert {selected_management_alert} status "
                f"saved as {new_status}."
            )

            st.rerun()

    else:
        st.info(
            "No alerts match the selected search and filter criteria."
        )
# =========================
# Audit Trail Viewer
# =========================

section("🧾 Alert Audit Trail")

st.write(
    "Review historical changes to alert investigation statuses."
)

audit_col1, audit_col2 = st.columns([2, 1])

with audit_col1:
    audit_search = st.text_input(
        "Search by Alert ID",
        placeholder="Enter an alert ID...",
        key="audit_search",
    )

with audit_col2:
    audit_limit = st.selectbox(
        "Records to display",
        [25, 50, 100, 250],
        index=1,
        key="audit_limit",
    )

if st.button("🔄 Refresh Audit Trail", key="refresh_audit"):
    st.rerun()

audit_history = get_audit_history()

if audit_history is None or (
    hasattr(audit_history, "empty") and audit_history.empty
) or (isinstance(audit_history, list) and len(audit_history) == 0):
    st.info(
        "No audit history is available yet. "
        "Change an alert's status to generate a history record."
    )

else:
    # Convert the returned history into a DataFrame if necessary.
    if isinstance(audit_history, list):
        audit_df = pd.DataFrame(audit_history)
    else:
        audit_df = audit_history.copy()

    if not audit_df.empty:
        # Search for a specific alert.
        if audit_search.strip():
            if "alert_id" in audit_df.columns:
                audit_df = audit_df[
                    audit_df["alert_id"]
                    .astype(str)
                    .str.contains(
                        audit_search.strip(),
                        case=False,
                        na=False,
                    )
                ]
            else:
                st.warning(
                    "The audit history does not contain an alert_id column."
                )

        # Show newest records first when a timestamp column exists.
        timestamp_candidates = [
            "changed_at",
            "timestamp",
            "created_at",
            "updated_at",
        ]

        timestamp_column = next(
            (
                column
                for column in timestamp_candidates
                if column in audit_df.columns
            ),
            None,
        )

        if timestamp_column:
            audit_df = audit_df.sort_values(
                timestamp_column,
                ascending=False,
            )

        st.metric("Audit Records", len(audit_df))

        if audit_df.empty:
            st.warning("No audit records match your search.")
        else:
            st.dataframe(
                audit_df.head(audit_limit),
                use_container_width=True,
                hide_index=True,
            )

            csv_data = audit_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="⬇️ Export Audit Trail (CSV)",
                data=csv_data,
                file_name="alert_audit_trail.csv",
                mime="text/csv",
                key="download_audit_trail",
            )
  
# =========================
# Alert Investigation Timeline
# =========================

section("🕒 Alert Investigation Timeline")

timeline_alert_id = st.text_input(
    "Enter Alert ID to view its timeline",
    placeholder="Enter the exact alert ID",
    key="timeline_alert_id",
)

if timeline_alert_id.strip():
    timeline = get_audit_history(
        alert_id=timeline_alert_id.strip(),
        limit=500,
    )

    if not timeline:
        st.info("No status-change history found for this alert.")
    else:
        st.caption("Status changes are shown newest first.")

        for event in timeline:
            with st.container(border=True):
                old_status = event["old_status"] or "Not previously set"

                st.markdown(
                    f"**{old_status} → {event['new_status']}**"
                )

                st.caption(
                    f"Changed at (UTC): {event['updated_at']}"
                )

                st.caption(
                    f"Alert ID: {event['alert_id']} "
                    f"| History record: {event['history_id']}"
                )
else:
    st.info("Enter an alert ID to view its investigation timeline.")
  
# =========================
# Alert Investigation Timeline
# =========================

section("🕒 Alert Investigation Timeline")


timeline_alert_id = st.text_input(
    "Enter Alert ID to view its timeline",
    placeholder="Enter the exact alert ID",
    key="investigation_timeline_search",
)


if timeline_alert_id.strip():
    timeline = get_audit_history(
        alert_id=timeline_alert_id.strip(),
        limit=500,
    )

    if not timeline:
        st.info(
            "No status-change history found for this alert."
        )
    else:
        st.caption("Status changes are shown newest first.")

        for event in timeline:
            with st.container(border=True):
                st.markdown(
                    f"**{event['old_status']} → "
                    f"{event['new_status']}**"
                )
                st.caption(
                    f"Changed at (UTC): {event['updated_at']}"
                )
                st.caption(
                    f"Alert ID: {event['alert_id']} "
                    f"| History record: {event['history_id']}"
                )
else:
    st.info("Enter an alert ID to view its investigation timeline.")
 
# =========================
# Audit Activity Dashboard
# =========================

section("📊 Audit Activity Dashboard")

audit_dashboard = get_audit_history(limit=500)

if not audit_dashboard:
    st.info("No audit activity recorded yet.")
else:
    audit_df = pd.DataFrame(audit_dashboard)

    total_changes = len(audit_df)
    unique_alerts = audit_df["alert_id"].nunique()

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Total Status Changes", total_changes)

    with col2:
        st.metric("Alerts Updated", unique_alerts)

    st.markdown("### Status Change Distribution")

    status_counts = (
        audit_df["new_status"]
        .value_counts()
        .rename_axis("Status")
        .reset_index(name="Changes")
    )

    st.bar_chart(
        status_counts,
        x="Status",
        y="Changes",
    )

    st.markdown("### Recent Audit Activity")

    recent_audit = audit_df.copy()
    recent_audit["updated_at"] = pd.to_datetime(
        recent_audit["updated_at"],
        errors="coerce",
        utc=True,
    )

    st.dataframe(
        recent_audit[
            [
                "updated_at",
                "alert_id",
                "old_status",
                "new_status",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )
   
# =========================
# Alert Export
# =========================

section("📥 Export Alert Records")

if not alerts.empty:
    export_df = alerts.copy()

    csv_data = export_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Alerts as CSV",
        data=csv_data,
        file_name="brute_force_alerts.csv",
        mime="text/csv",
        key="download_alert_records",
    )

    st.caption(
        "Export the current alert records for offline review and reporting."
    )
else:
    st.info("No alert records are currently available to export.")
   
# =========================
# Full Investigation Report Export
# =========================

section("📑 Full Investigation Report Export")

if st.button("Prepare Investigation Report", key="prepare_full_report"):

    # Export alert records
    alert_report = alerts.copy()

    # Export AI investigation history
    ai_history = st.session_state.get(
        "ai_investigation_history", []
    )

    ai_history_df = pd.DataFrame(ai_history)

    # Export audit history from SQLite
    audit_history = get_audit_history(limit=500)
    audit_history_df = pd.DataFrame(audit_history)

    # Store report data in session state
    st.session_state["full_report_alerts"] = alert_report
    st.session_state["full_report_ai_history"] = ai_history_df
    st.session_state["full_report_audit_history"] = audit_history_df

    st.success("Investigation report prepared successfully.")

if "full_report_alerts" in st.session_state:

    import io
    import zipfile

    report_buffer = io.BytesIO()

    with zipfile.ZipFile(
        report_buffer, mode="w", compression=zipfile.ZIP_DEFLATED
    ) as report_zip:

        report_zip.writestr(
            "alerts.csv",
            st.session_state["full_report_alerts"].to_csv(index=False),
        )

        report_zip.writestr(
            "ai_investigation_history.csv",
            st.session_state["full_report_ai_history"].to_csv(index=False),
        )

        report_zip.writestr(
            "audit_history.csv",
            st.session_state["full_report_audit_history"].to_csv(index=False),
        )

    st.download_button(
        label="Download Full Investigation Report",
        data=report_buffer.getvalue(),
        file_name="full_investigation_report.zip",
        mime="application/zip",
        key="download_full_investigation_report",
    )

    st.caption(
        "The ZIP file contains separate CSV files for alerts, "
        "AI investigation history, and audit history."
    )
 
# =========================
# PDF Incident Report
# =========================

from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


section("📄 PDF Incident Report")

if alerts.empty:
    st.info("No alerts are available for a PDF report.")
else:
    report_alerts = alerts.copy()

    # Create a readable label for each alert.
    report_alerts["report_label"] = (
        report_alerts.index.astype(str)
        + " | "
        + report_alerts["failed_attempts"].astype(str)
        + " failed attempts"
    )

    selected_report_label = st.selectbox(
        "Select an alert",
        options=report_alerts["report_label"].tolist(),
        key="pdf_incident_alert_selector",
    )

    selected_row = report_alerts[
        report_alerts["report_label"] == selected_report_label
    ].iloc[0]

    selected_alert_id = str(selected_row.name)
    selected_status = st.session_state.get(
        "alert_statuses", {}
    ).get(selected_alert_id, "New")

    st.write("**Alert ID:**", selected_alert_id)
    st.write(
        "**Severity:**",
        selected_row.get("severity", "Not available"),
    )
    st.write(
        "**Failed attempts:**",
        selected_row.get("failed_attempts", "Not available"),
    )
    st.write("**Current status:**", selected_status)

    if st.button(
        "Generate PDF Incident Report",
        key="generate_single_alert_pdf",
    ):
        pdf_buffer = BytesIO()

        styles = getSampleStyleSheet()
        story = []

        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        story.append(
            Paragraph("Security Incident Report", styles["Title"])
        )
        story.append(Spacer(1, 8 * mm))

        generated_at = datetime.now().astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )

        details = [
            ["Field", "Details"],
            ["Alert ID", selected_alert_id],
            [
                "Severity",
                str(selected_row.get("severity", "Not available")),
            ],
            [
                "Failed attempts",
                str(selected_row.get("failed_attempts", "Not available")),
            ],
            ["Investigation status", selected_status],
            ["Report generated", generated_at],
        ]

        safe_details = [
            [escape(str(value)) for value in row]
            for row in details
        ]

        details_table = Table(
            safe_details,
            colWidths=[55 * mm, 105 * mm],
        )
        details_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ])
        )

        story.append(details_table)
        story.append(Spacer(1, 8 * mm))

        story.append(
            Paragraph("AI Investigation Findings", styles["Heading2"])
        )

        ai_history = st.session_state.get(
            "ai_investigation_history", []
        )

        matching_findings = []

        for item in ai_history:
            item_text = str(item)
            if selected_alert_id in item_text:
                matching_findings.append(item)

        if matching_findings:
            for finding in matching_findings:
                story.append(
                    Paragraph(
                        escape(str(finding)),
                        styles["BodyText"],
                    )
                )
                story.append(Spacer(1, 4 * mm))
        else:
            story.append(
                Paragraph(
                    "No matching AI investigation findings were "
                    "found in the current session history.",
                    styles["BodyText"],
                )
            )

        story.append(Spacer(1, 8 * mm))
        story.append(
            Paragraph(
                "This report was generated from the application's "
                "currently available alert and investigation data.",
                styles["Italic"],
            )
        )

        doc.build(story)
        pdf_bytes = pdf_buffer.getvalue()
        pdf_buffer.close()

        st.download_button(
            label="Download PDF Incident Report",
            data=pdf_bytes,
            file_name=f"incident_report_{selected_alert_id}.pdf",
            mime="application/pdf",
            key="download_single_alert_pdf",
        )

# -----------------------------
# Risk Level Distribution
# -----------------------------
section("📊 Risk Level Distribution")

risk_distribution = alerts["severity"].value_counts().reset_index()
risk_distribution.columns = ["Risk Level", "Number of Alerts"]

risk_chart = px.bar(risk_distribution, x="Risk Level", y="Number of Alerts")
risk_chart = style_chart(
    risk_chart,
    "Risk Level Distribution",
    "Risk Level",
    "Number of Alerts"
)

# Display chart at the selected width

if CHART_WIDTH == 100:
    chart_area = st.container()
else:
    left_ratio = (100 - CHART_WIDTH) / 2
    left_space, chart_area, right_space = st.columns(
        [left_ratio, CHART_WIDTH, left_ratio]
    )

with chart_area:
    st.plotly_chart(
        risk_chart,
        use_container_width=True,
        theme=None
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
                ai_result = analyze_alert(selected_alert.to_dict())

            unavailable_prefixes = (
                "AI analysis unavailable:",
                "AI service temporarily unavailable:",
                "AI analysis failed:",
            )

            if not is_successful_analysis(ai_result):
              st.error(
                 ai_result or "AI analysis returned an empty result."
            )
            else:

                add_investigation_history(
                    history=st.session_state.ai_investigation_history,
                    alert_id=selected_alert_id,
                    result=ai_result,
                    severity=selected_alert["severity"],
                    investigation_id=str(uuid.uuid4())[:8].upper(),
                    timestamp=datetime.now().astimezone().isoformat(
                   
                        timespec="seconds"

                    ),
                    notes="",
                )

                st.success(
                    "AI analysis returned. Review the findings below."
                )

                st.markdown(
                    '<div class="ai-analysis-title">'
                    'AI Security Analysis</div>',
                    unsafe_allow_html=True
                )

                with st.container(border=True):
                    if (
                        "Attack type undetermined from the available evidence."
                        in ai_result
                    ):
                        st.warning(
                            "⚠️ INVESTIGATION STATUS: ATTACK TYPE UNDETERMINED",
                            icon="🔎"
                        )
                    else:
                        st.info(
                            "🔎 INVESTIGATION STATUS: REVIEW AI FINDINGS"
                        )

                    st.divider()
                    st.markdown(ai_result)
    else:
        st.info("No alerts are available for AI analysis.")


# -----------------------------
# AI Investigation History
# -----------------------------
st.divider()
section("📚 AI Investigation History")

st.markdown(
    """
    <style>
    /* Investigation history and report text */
    div[data-testid="stExpander"] summary,
    div[data-testid="stExpander"] summary *,
    div[data-testid="stExpander"] [data-testid="stMarkdownContainer"],
    div[data-testid="stExpander"] [data-testid="stMarkdownContainer"] *,
    div[data-testid="stExpander"] label,
    div[data-testid="stExpander"] label *,
    div[data-testid="stExpander"] textarea {
        font-size: 30px !important;
        line-height: 1.5 !important;
    }

    /* Export button and all nested label elements */
    div[data-testid="stDownloadButton"] button,
    div[data-testid="stDownloadButton"] button *,
    div[data-testid="stDownloadButton"] button p {
        font-size: 30px !important;
        line-height: 1.5 !important;
    }

    div[data-testid="stDownloadButton"] button {
        min-height: 60px !important;
        height: auto !important;
    }
    
    /* Investigation ID and timestamp: minimum 25px */
    div[data-testid="stExpander"] [data-testid="stCaptionContainer"],
    div[data-testid="stExpander"] [data-testid="stCaptionContainer"] * {
        font-size: 25px !important;
        line-height: 1.5 !important;
    }
    
    /* Severity indicators: maintain the 30px standard */
    div[data-testid="stExpander"] [data-testid="stAlert"],
    div[data-testid="stExpander"] [data-testid="stAlert"] * {
       font-size: 30px !important;
       line-height: 1.5 !important;
}

    </style>
    """,
    unsafe_allow_html=True
)

if st.session_state.ai_investigation_history:

    for i, investigation in enumerate(
        reversed(st.session_state.ai_investigation_history), start=1
    ):
        with st.expander(
            f"Investigation {i} — Alert {investigation['alert_id']}"
        ):
           
            severity = investigation.get("severity", "UNKNOWN")

            if severity == "HIGH":
                st.error(f"🔴 SEVERITY: {severity}")
            elif severity == "MEDIUM":
                st.warning(f"🟠 SEVERITY: {severity}")
            elif severity == "LOW":
                st.info(f"🟡 SEVERITY: {severity}")
            else:
                st.caption("Severity: UNKNOWN")
 
            st.caption(
                f"Investigation ID: "
                f"{investigation.get('investigation_id', 'N/A')}"
            )
            st.caption(
                f"Timestamp: {investigation.get('timestamp', 'N/A')}"
            )

            st.markdown(investigation["result"])

            st.divider()
            st.subheader("Analyst Notes")

            notes_key = (
                f"analyst_notes_{investigation.get('investigation_id', i)}"
            )

            if notes_key not in st.session_state:
                st.session_state[notes_key] = investigation.get(
                    "analyst_notes", ""
                )

            investigation["analyst_notes"] = st.text_area(
                "Record your observations or follow-up actions",
                height=150,
                key=notes_key
            )

    export_data = [
        {
            "investigation_id": item.get("investigation_id", "N/A"),
            "timestamp": item.get("timestamp", "N/A"),
            "alert_id": item["alert_id"],
            "severity": item.get("severity", "N/A"),
            "ai_report": item["result"],
            "analyst_notes": item.get("analyst_notes", ""),
        }
        for item in st.session_state.ai_investigation_history
    ]

    st.download_button(
        label="📥 Export Investigation History",
        data=json.dumps(
            export_data, indent=4, ensure_ascii=False
        ),
        file_name="soc_investigation_history.json",
        mime="application/json",
        key="export_investigation_history"
    )

else:
    st.info("No AI investigations recorded yet.")



