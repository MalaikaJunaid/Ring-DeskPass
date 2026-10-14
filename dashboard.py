import sqlite3
from datetime import UTC, datetime

import pandas as pd
import streamlit as st

# Configure the page layout for a professional dashboard look
st.set_page_config(page_title="DeskPass Reception Portal", page_icon="🏢", layout="wide")

st.title("🏢 DeskPass Reception Portal")
st.markdown("Live access control monitoring, automated AI orchestration, and historical analytics.")
st.divider()

DB_FILE = "ring_deskpass.db"

# The run_every parameter automates this fragment to fetch live updates every 3 seconds 
@st.fragment(run_every="3s")
def render_live_dashboard():
    try:
        # 1. Connect to the local SQLite database
        conn = sqlite3.connect(DB_FILE)
        
        # 2. Use Pandas to query the historical access logs
        query = "SELECT timestamp, event_id, identity, status FROM access_logs ORDER BY timestamp DESC"
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        if df.empty:
            st.info("No access logs found. Waiting for webhook events...")
            return

        # 3. Parse timestamps to isolate "Today's" metrics
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        today_date = datetime.now(UTC).date()
        df_today = df[df['timestamp'].dt.date == today_date]

        # 4. Calculate KPI Metrics
        total_today = len(df_today)
        approved_today = len(df_today[df_today['status'] == "APPROVED"])
        denied_today = len(df_today[df_today['status'] == "DENIED"])

        # 5. Render the Business Metrics Row
        st.subheader("📊 Today's Analytics")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Visitors Today", total_today)
        col2.metric("✅ Approved Entries", approved_today)
        col3.metric("❌ Denied Entries", denied_today)

        st.divider()

        # 6. Render the Historical Data Table
        st.subheader("📋 Immutable Access Audit Log")
        
        # Clean up the dataframe for presentation
        display_df = df.copy()
        display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        display_df.rename(columns={
            'timestamp': 'Date & Time', 
            'event_id': 'Webhook Event ID', 
            'identity': 'Visitor Identity', 
            'status': 'Verification Status'
        }, inplace=True)
        
        # Display as an interactive, full-width table
        st.dataframe(
            display_df,
            width="stretch",
            hide_index=True
        )
        
    except sqlite3.OperationalError:
        st.warning("Database not initialized yet. Please trigger a webhook payload to create the first record.")
    except (sqlite3.Error, pd.errors.EmptyDataError, ValueError, KeyError) as e:
        st.error(f"Error loading dashboard: {e}")
        
# Render the fragment
render_live_dashboard()