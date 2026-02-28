import requests
import urllib3
import streamlit as st
import datetime
import pandas as pd
import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from google import genai

# Disable strict SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(page_title="MLSecOps Command Center", page_icon="🛡️", layout="wide")

st.title("🛡️ Unified MLSecOps Command Center")
st.markdown("Welcome to the automated SOC dashboard. Configure your integrations in the sidebar.")
st.markdown("---")

# --- 2. THE SETTINGS SIDEBAR ---
st.sidebar.header("⚙️ Global Configuration")

st.sidebar.subheader("1. OpenSearch / Wazuh SIEM")
wazuh_ip = st.sidebar.text_input("SIEM IP Address", value="192.168.56.10")
wazuh_user = st.sidebar.text_input("Username", value="admin")
wazuh_pass = st.sidebar.text_input("Password", type="password")

st.sidebar.subheader("2. AI & Automation Endpoints")
gemini_api_key = st.sidebar.text_input("Google Gemini API Key", type="password")
webhook_url = st.sidebar.text_input("SOAR Webhook URL")

st.sidebar.subheader("3. Threat Hunting Window")
today = datetime.date.today()
start_date = st.sidebar.date_input("Start Date", today - datetime.timedelta(days=2))
end_date = st.sidebar.date_input("End Date", today)

st.sidebar.subheader("4. Threat Severity Filter")
filter_severity = st.sidebar.checkbox("Enable Severity Filter", value=False)
min_rule_level = st.sidebar.slider("Minimum Rule Level (1-15)", min_value=1, max_value=15, value=3, disabled=not filter_severity)

st.sidebar.success("Configuration loaded securely.")

# --- 3. THE NAVIGATION TABS ---
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 System Health",
    "🌐 Project 1: Network Anomalies",
    "🥷 Project 2/3: Sequence Triage",
    "👤 Project 5: UEBA Analytics"
])

# --- TAB 1: HEALTH ---
with tab1:
    st.header("SIEM Infrastructure Health")
    if st.button("🔄 Test SIEM Connection"):
        if not wazuh_pass:
            st.warning("⚠️ Please enter your Wazuh password in the sidebar!")
        else:
            with st.spinner("Pinging OpenSearch Cluster..."):
                try:
                    url = f"https://{wazuh_ip}:9201/_cluster/health"
                    response = requests.get(url, auth=(wazuh_user, wazuh_pass), verify=False, timeout=5)
                    if response.status_code == 200:
                        health_data = response.json()
                        st.success(f"✅ Connection Successful! Cluster Status: **{health_data['status'].upper()}**")
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Nodes Online", health_data['number_of_nodes'])
                        col2.metric("Active Shards", health_data['active_shards'])
                        col3.metric("Pending Tasks", health_data['number_of_pending_tasks'])
                    else:
                        st.error("❌ Connection Failed.")
                except Exception as e:
                    st.error(f"❌ Critical Error: {e}")

# --- TAB 2: ISOLATION FOREST ---
with tab2:
    st.header("Unsupervised ML: Firewall Anomaly Detection")
    if filter_severity:
        st.write(f"Analyzing FortiGate logs with a Severity Level of **{min_rule_level} or higher**.")
    else:
        st.write("Analyzing **ALL** FortiGate logs (Severity Filter Disabled).")

    if st.button("🚀 Run Firewall Anomaly Detection"):
        if not wazuh_pass:
            st.warning("⚠️ Please enter your SIEM password!")
        else:
            with st.spinner("Fetching logs and training AI..."):
                try:
                    url = f"https://{wazuh_ip}:9201/wazuh-alerts-*/_search"
                    must_conditions = [
                        {"match": {"rule.groups": "fortigate"}},
                        {"range": {
                            "timestamp": {
                                "gte": f"{start_date}T00:00:00Z",
                                "lte": f"{end_date}T23:59:59Z"
                            }
                        }}
                    ]
                    if filter_severity:
                        must_conditions.append({"range": {"rule.level": {"gte": min_rule_level}}})

                    query = {
                        "size": 5000,
                        "query": {"bool": {"must": must_conditions}},
                        "sort": [{"timestamp": {"order": "desc"}}]
                    }
                    response = requests.get(url, auth=(wazuh_user, wazuh_pass), headers={'Content-Type': 'application/json'}, data=json.dumps(query), verify=False)

                    if response.status_code == 200:
                        hits = response.json()['hits']['hits']
                        if len(hits) == 0:
                            st.warning("No firewall logs found. Try expanding the date range or disabling the severity filter.")
                        else:
                            df = pd.json_normalize([hit['_source'] for hit in hits])

                            # TWEAK 2: The Attack Timeline Histogram!
                            if 'timestamp' in df.columns:
                                st.subheader("📈 Network Traffic Volume Over Time")
                                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                                volume_data = df.groupby(df['timestamp'].dt.floor('Min')).size()
                                st.bar_chart(volume_data)

                            port_col, src_col = 'data.dstport', 'data.srcport'
                            if port_col in df.columns and src_col in df.columns:
                                df_clean = df.dropna(subset=[port_col, src_col]).copy()
                                df_clean[port_col] = pd.to_numeric(df_clean[port_col], errors='coerce')
                                df_clean[src_col] = pd.to_numeric(df_clean[src_col], errors='coerce')
                                df_clean = df_clean.dropna(subset=[port_col, src_col])

                                if len(df_clean) > 5:
                                    model = IsolationForest(contamination=0.05, random_state=42)
                                    df_clean['Anomaly_Score'] = model.fit_predict(df_clean[[port_col, src_col]])
                                    anomalies = df_clean[df_clean['Anomaly_Score'] == -1]

                                    st.success(f"✅ AI Analysis Complete! Processed {len(df_clean)} connections.")
                                    st.subheader("📊 Firewall Anomaly Scatter Plot")
                                    chart_df = df_clean.rename(columns={port_col: 'Destination Port', src_col: 'Source Port'})
                                    chart_df['Status'] = chart_df['Anomaly_Score'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
                                    st.scatter_chart(chart_df, x='Destination Port', y='Source Port', color='Status')
                                else:
                                    st.warning("Not enough numerical data to train.")
                            else:
                                st.error("Required port columns not found.")
                except Exception as e:
                    st.error(f"Error: {e}")

# --- TAB 3: HYBRID SEQUENCE TRIAGE ---
with tab3:
    st.header("🥷 Behavioral Triage & SOAR")

    analysis_mode = st.radio("Select Threat Hunting Mode:", ["🔴 Live Real-Time Monitoring", "⏪ Historical Forensic Analysis"], horizontal=True)

    if st.button("🚨 Analyze Network Sequence & Trigger SOAR"):
        if not gemini_api_key or not wazuh_pass:
            st.error("⚠️ Please enter your Gemini API Key and Wazuh Password in the sidebar.")
        else:
            with st.status("🔍 Step 1: Extracting Behavioral Sequence...", expanded=True) as status:
                try:
                    url = f"https://{wazuh_ip}:9201/wazuh-alerts-*/_search"
                    must_conditions_tab3 = [{"match": {"rule.groups": "fortigate"}}]
                    if filter_severity:
                        must_conditions_tab3.append({"range": {"rule.level": {"gte": min_rule_level}}})
                    if analysis_mode == "⏪ Historical Forensic Analysis":
                        must_conditions_tab3.append({"range": {"timestamp": {"gte": f"{start_date}T00:00:00Z", "lte": f"{end_date}T23:59:59Z"}}})

                    query = {"size": 20, "query": {"bool": {"must": must_conditions_tab3}}, "sort": [{"timestamp": {"order": "desc"}}]}
                    response = requests.get(url, auth=(wazuh_user, wazuh_pass), headers={'Content-Type': 'application/json'}, data=json.dumps(query), verify=False)

                    if response.status_code == 200:
                        hits = response.json()['hits']['hits']
                        if len(hits) == 0:
                            st.warning("No firewall data found for the selected filters.")
                            st.stop()

                        sequence_list = []
                        target_ip = hits[0]['_source']['data'].get('srcip', 'Unknown_IP')
                        for hit in reversed(hits):
                            app = hit['_source']['data'].get('app', 'Unknown_App')
                            if app not in sequence_list:
                                sequence_list.append(app)

                        live_sequence = " ➔ ".join(sequence_list)
                        mode_text = "Live" if analysis_mode == "🔴 Live Real-Time Monitoring" else "Historical"
                        st.success(f"Captured {mode_text} Sequence for IP {target_ip}:\n**{live_sequence}**")

                        # TWEAK 3: VirusTotal OSINT Integration!
                        vt_url = f"https://www.virustotal.com/gui/search/{target_ip}"
                        st.markdown(f"**[🌍 Click to scan IP {target_ip} on VirusTotal]({vt_url})**")

                        alert_payload = {
                            "timestamp": datetime.datetime.now().isoformat(),
                            "ai_model": f"{mode_text} Behavioral Sequence Analyzer",
                            "alert_type": "Anomalous Network Sequence Detected",
                            "target_host_ip": target_ip,
                            "network_sequence": live_sequence,
                            "automated_action_taken": "BLOCK_IP_AT_FIREWALL",
                        }
                        status.update(label="Step 1 Complete", state="complete")
                    else:
                        st.error("Failed to fetch data.")
                        st.stop()
                except Exception as e:
                    st.error(f"Database error: {e}")
                    st.stop()

            with st.status("⚡ Step 2: Executing SOAR Playbook...", expanded=True) as status:
                if webhook_url:
                    try:
                        requests.post(webhook_url, data=json.dumps(alert_payload), headers={'Content-Type': 'application/json'})
                        st.success("✅ Containment Successful!")
                    except:
                        st.warning("Webhook failed.")
                else:
                    st.info("No Webhook provided. Skipping.")
                status.update(label="Step 2 Complete", state="complete")

            with st.status("🧠 Step 3: Generating AI Incident Report...", expanded=True) as status:
                try:
                    client = genai.Client(api_key=gemini_api_key)
                    prompt = f"You are a SOC Commander. Analyze this {mode_text.lower()} firewall sequence. Is it normal or data exfiltration? {json.dumps(alert_payload)}"
                    response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
                    st.success("✅ AI Report Generated!")
                    status.update(label="Step 3 Complete", state="complete")

                    st.markdown("---")
                    st.markdown(response.text)
                    st.markdown("---")

                    # TWEAK 1: The Executive Export Download Button!
                    st.download_button(
                        label="💾 Download Executive Incident Report (.md)",
                        data=response.text,
                        file_name=f"Incident_Report_{target_ip}_{datetime.date.today()}.md",
                        mime="text/markdown"
                    )

                except Exception as e:
                    st.error(f"API Error: {e}")
                    status.update(label="Step 3 Failed", state="error")

# --- TAB 4: UEBA IDENTITY ANALYTICS (K-MEANS) ---
with tab4:
    st.header("👤 User & Entity Behavior Analytics (UEBA)")
    st.write("This module uses K-Means Clustering to build behavioral profiles for every IP and detects entities acting outside of normal company baseline behavior.")

    if st.button("🧠 Run K-Means Clustering Analytics"):
        if not wazuh_pass:
            st.warning("⚠️ Please enter your SIEM password!")
        else:
            with st.spinner("Fetching 24h telemetry and building profiles..."):
                try:
                    url = f"https://{wazuh_ip}:9201/wazuh-alerts-*/_search"
                    query = {
                        "size": 10000,
                        "query": {
                            "bool": {
                                "must": [
                                    {"match": {"rule.groups": "fortigate"}},
                                    {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}}
                                ]
                            }
                        }
                    }
                    response = requests.get(url, auth=(wazuh_user, wazuh_pass), headers={'Content-Type': 'application/json'}, data=json.dumps(query), verify=False)

                    if response.status_code == 200:
                        hits = response.json()['hits']['hits']
                        if len(hits) == 0:
                            st.warning("No data found for UEBA profiling.")
                        else:
                            df = pd.json_normalize([hit['_source'] for hit in hits])
                            df['data.sentbyte'] = pd.to_numeric(df['data.sentbyte'], errors='coerce').fillna(0)
                            df['data.dstport'] = pd.to_numeric(df['data.dstport'], errors='coerce').fillna(0)

                            ueba_df = df.groupby('data.srcip').agg({
                                'data.app': 'nunique',
                                'data.sentbyte': 'sum',
                                'data.dstport': 'mean'
                            }).reset_index()

                            ueba_df.columns = ['IP', 'App_Diversity', 'Total_Upload', 'Avg_Port']

                            if len(ueba_df) > 2:
                                features = ueba_df[['App_Diversity', 'Total_Upload', 'Avg_Port']]
                                scaler = StandardScaler()
                                scaled_features = scaler.fit_transform(features)

                                kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
                                ueba_df['Cluster'] = kmeans.fit_predict(scaled_features)

                                distances = []
                                for i, row in enumerate(scaled_features):
                                    center = kmeans.cluster_centers_[ueba_df['Cluster'].iloc[i]]
                                    distances.append(np.linalg.norm(row - center))
                                ueba_df['Distance'] = distances

                                threshold = ueba_df['Distance'].quantile(0.95)
                                ueba_df['Is_Anomaly'] = ueba_df['Distance'] > threshold

                                st.success(f"✅ Profiling Complete! Analyzed {len(ueba_df)} unique entities.")

                                anomalies = ueba_df[ueba_df['Is_Anomaly'] == True]
                                if anomalies.empty:
                                    st.info("No anomalous behavior detected. All laptops acting normally.")
                                else:
                                    st.error(f"🚨 Detected {len(anomalies)} Highly Anomalous Entities!")
                                    st.dataframe(anomalies.style.highlight_max(axis=0, color='red'))

                                # Visual Scatter Plot: App Diversity vs Avg Port
                                st.subheader("📊 Entity Behavior Clusters")
                                chart_df = ueba_df.copy()
                                chart_df['Status'] = chart_df['Is_Anomaly'].apply(lambda x: 'Anomalous (Outlier)' if x else 'Normal Behavior')
                                st.scatter_chart(chart_df, x='App_Diversity', y='Avg_Port', color='Status')
                            else:
                                st.warning("Not enough unique IPs to run clustering.")
                except Exception as e:
                    st.error(f"Error executing UEBA: {e}")