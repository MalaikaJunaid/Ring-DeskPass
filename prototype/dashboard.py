import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from demo_simulator import MAX_SNAPSHOT_BYTES, create_sample_badge, submit_demo_event

load_dotenv()

st.set_page_config(
    page_title="DeskPass | Reception",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

DB_FILE = Path(
    os.getenv("DESKPASS_DB_FILE", str(Path(__file__).resolve().with_name("ring_deskpass.db")))
)
API_URL = os.getenv("DESKPASS_API_URL", "http://localhost:8000").rstrip("/")
REVIEW_TOKEN = os.getenv("DESKPASS_REVIEW_TOKEN", "")

st.markdown(
    """
    <style>
    :root {
        --ink: #17253a;
        --muted: #718096;
        --line: #e5ebf2;
        --surface: #ffffff;
        --canvas: #f4f7fb;
    }

    [data-testid="stAppViewContainer"] {
        background: var(--canvas);
        color: var(--ink);
        font-family: Inter, "Segoe UI", sans-serif;
    }
    [data-testid="stHeader"] {
        background: transparent;
    }
    .block-container {
        max-width: 1440px;
        padding: 2.2rem 3rem 3rem;
    }
    h1, h2, h3 {
        color: var(--ink);
        font-family: Inter, "Segoe UI", sans-serif;
        letter-spacing: -0.035em;
    }
    .brand-row {
        align-items: center;
        display: flex;
        gap: 14px;
        margin-bottom: 1.5rem;
    }
    .brand-mark {
        align-items: center;
        background: #1c3454;
        border-radius: 12px;
        color: #fff;
        display: flex;
        font-family: Inter, "Segoe UI", sans-serif;
        font-size: 15px;
        font-weight: 800;
        height: 42px;
        justify-content: center;
        letter-spacing: -0.04em;
        width: 42px;
    }
    .brand-name {
        color: var(--ink);
        font-family: Inter, "Segoe UI", sans-serif;
        font-size: 18px;
        font-weight: 800;
        letter-spacing: -0.04em;
        line-height: 1.2;
    }
    .brand-caption {
        color: var(--muted);
        font-size: 12px;
        margin-top: 3px;
    }
    .page-heading {
        color: var(--ink);
        font-family: Inter, "Segoe UI", sans-serif;
        font-size: clamp(28px, 3vw, 38px);
        font-weight: 800;
        letter-spacing: -0.055em;
        line-height: 1.15;
        margin: 0;
    }
    .page-subtitle {
        color: var(--muted);
        font-size: 15px;
        margin: 8px 0 22px;
    }
    .live-indicator {
        align-items: center;
        color: #53647b;
        display: flex;
        font-size: 12px;
        font-weight: 700;
        gap: 8px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
    }
    .live-dot {
        background: #1caa72;
        border-radius: 50%;
        box-shadow: 0 0 0 4px #def5e9;
        height: 8px;
        width: 8px;
    }
    .section-label {
        color: #34445b;
        font-family: Inter, "Segoe UI", sans-serif;
        font-size: 17px;
        font-weight: 700;
        letter-spacing: -0.025em;
        margin: 1.1rem 0 0.8rem;
    }
    [data-testid="stMetric"] {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 14px;
        box-shadow: 0 2px 8px rgba(29, 48, 75, 0.035);
        min-height: 126px;
        padding: 18px 20px;
    }
    [data-testid="stMetricLabel"] {
        color: var(--muted);
        font-size: 13px;
        font-weight: 600;
    }
    [data-testid="stMetricValue"] {
        color: var(--ink);
        font-family: Inter, "Segoe UI", sans-serif;
        font-size: 30px;
        font-weight: 800;
        letter-spacing: -0.04em;
    }
    [data-testid="stMetricDelta"] {
        font-size: 12px;
    }
    [data-testid="stDataFrame"] {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 14px;
        overflow: hidden;
    }
    [data-testid="stTextInput"] input,
    [data-testid="stSelectbox"] [data-baseweb="select"] > div {
        background: var(--surface);
        border-color: var(--line);
        border-radius: 10px;
    }
    div[data-testid="stAlert"] {
        border-radius: 12px;
    }
    @media (max-width: 700px) {
        .block-container {
            padding: 1.3rem 1rem 2rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="brand-row">
        <div class="brand-mark">DP</div>
        <div>
            <div class="brand-name">DeskPass</div>
            <div class="brand-caption">Reception operations</div>
        </div>
    </div>
    <h1 class="page-heading">Access overview</h1>
    <p class="page-subtitle">Monitor visitor verification and review the latest access activity.</p>
    """,
    unsafe_allow_html=True,
)

with st.expander("Run a device-free demo event", expanded=False):
    st.caption(
        "Send a signed sample image through the same local intake and review queue. "
        "This demonstrates the workflow; it is not an official Ring simulator."
    )
    with st.form("demo_event_form"):
        demo_image = st.file_uploader(
            "Optional visitor badge image",
            type=["jpg", "jpeg", "png"],
            help="Images are validated locally and removed after processing.",
        )
        use_sample = st.checkbox(
            "Use the synthetic sample image if no image is uploaded",
            value=True,
        )
        send_demo = st.form_submit_button("Send demo event", type="primary")
    if send_demo:
        if demo_image is not None:
            if demo_image.size > MAX_SNAPSHOT_BYTES:
                st.error("Choose an image that is 10 MB or smaller.")
                image_bytes = None
            else:
                image_bytes = demo_image.getvalue()
        elif use_sample:
            image_bytes = create_sample_badge()
        else:
            image_bytes = None
            st.error("Upload an image or choose the synthetic sample.")
        if image_bytes is not None:
            try:
                response = submit_demo_event(image_bytes)
            except (ValueError, OSError, httpx.HTTPError) as error:
                st.error(f"Demo event was not accepted: {error}")
            else:
                st.success(
                    f"Event {response['event_id']} accepted and queued "
                    f"({response['status']}). The dashboard will refresh with its result."
                )


def status_style(status: str) -> str:
    if status == "APPROVED":
        return "color: #14764c; background-color: #e8f7ef; font-weight: 700;"
    if status == "DENIED":
        return "color: #a83c43; background-color: #fff0f0; font-weight: 700;"
    return "color: #53647b; font-weight: 600;"


def submit_review(event_id: str, decision: str, reviewer: str) -> None:
    try:
        response = httpx.post(
            f"{API_URL}/review/{quote(event_id, safe='')}",
            json={"decision": decision, "reviewer": reviewer},
            headers={"Authorization": f"Bearer {REVIEW_TOKEN}"},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as error:
        st.error(f"Review action could not be saved: {error}")
        return
    st.success(f"Event {event_id} marked {decision.lower()}.")


@st.fragment(run_every="3s")
def render_live_dashboard() -> None:
    refreshed_at = datetime.now(UTC).strftime("%H:%M:%S UTC")
    st.markdown(
        f"""
        <div class="live-indicator">
            <span class="live-dot"></span>
            Live monitoring
            <span style="color:#a2adbc;font-weight:400;letter-spacing:0;text-transform:none">
                · refreshed {refreshed_at}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not DB_FILE.is_file():
        st.info("The access log database has not been created yet. Events will appear after the first webhook is processed.")
        return

    try:
        with closing(
            sqlite3.connect(f"file:{DB_FILE.as_posix()}?mode=ro", uri=True)
        ) as connection:
            access_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(access_logs)")
            }
            optional_columns = [
                f"{column}" if column in access_columns else f"NULL AS {column}"
                for column in ("reviewed_by", "decision_detail")
            ]
            df = pd.read_sql_query(
                f"""
                SELECT timestamp, event_id, identity, status, redacted_evidence,
                       pii_scrubbed_count, {", ".join(optional_columns)}
                FROM access_logs AS current
                WHERE id = (
                    SELECT MAX(id)
                    FROM access_logs AS latest
                    WHERE latest.event_id = current.event_id
                )
                ORDER BY timestamp DESC
                """,
                connection,
            )
            try:
                queue_counts = dict(
                    connection.execute(
                        "SELECT status, COUNT(*) FROM processing_jobs GROUP BY status"
                    ).fetchall()
                )
            except sqlite3.OperationalError as error:
                if "no such table: processing_jobs" not in str(error).lower():
                    raise
                queue_counts = {}
    except sqlite3.OperationalError as error:
        if "no such table: access_logs" in str(error).lower():
            st.info("The access log table is not initialized yet. Process a webhook to create the first record.")
            return
        st.error(f"Unable to read the access log database: {error}")
        return
    except (sqlite3.Error, pd.errors.DatabaseError) as error:
        st.error(f"Unable to read the access log database: {error}")
        return

    if df.empty:
        st.markdown('<div class="section-label">Today</div>', unsafe_allow_html=True)
        st.metric("Events being processed", queue_counts.get("QUEUED", 0) + queue_counts.get("PROCESSING", 0))
        st.info("No access events have been recorded today. New activity will appear here automatically.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    invalid_timestamps = int(df["timestamp"].isna().sum())
    valid_df = df.dropna(subset=["timestamp"]).copy()
    now = pd.Timestamp.now(tz="UTC")
    today_df = valid_df[valid_df["timestamp"].dt.date == now.date()]

    total_today = len(today_df)
    approved_today = int((today_df["status"] == "APPROVED").sum())
    denied_today = int((today_df["status"] == "DENIED").sum())
    pending_today = int((today_df["status"] == "PENDING_REVIEW").sum())
    approval_rate = (approved_today / total_today * 100) if total_today else 0

    st.markdown('<div class="section-label">Today at a glance</div>', unsafe_allow_html=True)
    metric_cols = st.columns(6)
    metric_cols[0].metric("Total visitors", total_today)
    metric_cols[1].metric("Approved", approved_today)
    metric_cols[2].metric("Denied", denied_today)
    metric_cols[3].metric("Pending review", pending_today)
    metric_cols[4].metric(
        "In processing",
        queue_counts.get("QUEUED", 0) + queue_counts.get("PROCESSING", 0),
    )
    metric_cols[5].metric("Approval rate", f"{approval_rate:.0f}%")

    pending_df = valid_df[valid_df["status"] == "PENDING_REVIEW"].head(50)
    if not pending_df.empty:
        st.markdown('<div class="section-label">Reception review</div>', unsafe_allow_html=True)
        if len(valid_df[valid_df["status"] == "PENDING_REVIEW"]) > len(pending_df):
            st.caption("Showing the 50 most recent pending review events.")
        if not REVIEW_TOKEN:
            st.warning("Review actions are disabled until DESKPASS_REVIEW_TOKEN is configured for the dashboard.")
        else:
            reviewer = st.text_input(
                "Reviewer name",
                placeholder="Enter your name to record review decisions",
                key="reviewer_name",
            ).strip()
            for _, pending in pending_df.iterrows():
                event_id = str(pending["event_id"])
                identity = str(pending["identity"])
                with st.container(border=True):
                    review_cols = st.columns([2, 2, 1, 1])
                    review_cols[0].markdown(f"**Possible match:** {identity}")
                    review_cols[1].caption(f"Event {event_id} · {pending['timestamp']:%Y-%m-%d %H:%M UTC}")
                    evidence = str(pending.get("redacted_evidence") or "").strip()
                    if evidence:
                        st.caption(f"Sanitized evidence: {evidence}")
                    approve = review_cols[2].button(
                        "Approve",
                        key=f"approve_{event_id}",
                        disabled=len(reviewer) < 2,
                        type="primary",
                    )
                    deny = review_cols[3].button(
                        "Deny",
                        key=f"deny_{event_id}",
                        disabled=len(reviewer) < 2,
                    )
                    if approve:
                        submit_review(event_id, "APPROVED", reviewer)
                    elif deny:
                        submit_review(event_id, "DENIED", reviewer)

    st.markdown('<div class="section-label">Access activity</div>', unsafe_allow_html=True)
    filter_cols = st.columns([1, 1, 2])
    period = filter_cols[0].selectbox(
        "Time period",
        ["Today", "Last 7 days", "Last 30 days", "All time"],
        label_visibility="collapsed",
    )
    status_filter = filter_cols[1].selectbox(
        "Verification status",
        ["All statuses", "Approved", "Denied", "Pending review", "Failed"],
        label_visibility="collapsed",
    )
    search = filter_cols[2].text_input(
        "Search access activity",
        placeholder="Search visitor or event ID",
        label_visibility="collapsed",
    ).strip().casefold()

    filtered_df = valid_df
    if period == "Today":
        filtered_df = filtered_df[filtered_df["timestamp"].dt.date == now.date()]
    elif period == "Last 7 days":
        filtered_df = filtered_df[filtered_df["timestamp"] >= now - pd.Timedelta(days=7)]
    elif period == "Last 30 days":
        filtered_df = filtered_df[filtered_df["timestamp"] >= now - pd.Timedelta(days=30)]

    if status_filter != "All statuses":
        filtered_df = filtered_df[
            filtered_df["status"] == status_filter.upper().replace(" ", "_")
        ]
    if search:
        search_match = (
            filtered_df["identity"].fillna("").astype(str).str.casefold().str.contains(search, regex=False)
            | filtered_df["event_id"].fillna("").astype(str).str.casefold().str.contains(search, regex=False)
        )
        filtered_df = filtered_df[search_match]

    if invalid_timestamps:
        st.warning(f"{invalid_timestamps} access record(s) have invalid timestamps and are excluded from the dashboard.")

    if filtered_df.empty:
        st.info("No access events match these filters.")
        return

    display_df = filtered_df.head(500).copy()
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    display_df.rename(
        columns={
            "timestamp": "Date and time",
            "event_id": "Event ID",
            "identity": "Visitor",
            "status": "Status",
            "pii_scrubbed_count": "PII items redacted",
            "reviewed_by": "Reviewed by",
            "decision_detail": "Decision detail",
        },
        inplace=True,
    )
    styled_df = display_df.style.map(status_style, subset=["Status"])
    st.dataframe(
        styled_df,
        width="stretch",
        hide_index=True,
        height=min(42 + len(display_df) * 36, 560),
        column_config={
            "Date and time": st.column_config.TextColumn("Date and time", width="medium"),
            "Event ID": st.column_config.TextColumn("Event ID", width="medium"),
            "Visitor": st.column_config.TextColumn("Visitor", width="medium"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "PII items redacted": st.column_config.NumberColumn(
                "PII items redacted",
                help="Count of sensitive text patterns removed before this event was logged.",
                width="small",
            ),
            "Reviewed by": st.column_config.TextColumn("Reviewed by", width="small"),
            "Decision detail": st.column_config.TextColumn("Decision detail", width="large"),
        },
    )
    st.caption(f"Showing {len(display_df)} of {len(filtered_df)} matching events. The table is limited to the latest 500.")


render_live_dashboard()
