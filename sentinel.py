import requests
import urllib3
import datetime
import pandas as pd
import json
import smtplib
from email.mime.text import MIMEText
from sklearn.ensemble import IsolationForest
from google import genai
# Disable strict SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ==========================================
# ⚙️ CONFIGURATION ZONE (FILL THIS IN)
# ==========================================
# 1. SIEM Config
WAZUH_IP = "192.168.56.10"
WAZUH_USER = "admin"
WAZUH_PASS = "YOUR_WAZUH_PASSWORD"
# 2. AI Config
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
# 3. Notification Config
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"
# Email Config (Gmail Example)
EMAIL_SENDER = "your.email@gmail.com"
EMAIL_PASSWORD = "YOUR_16_CHAR_APP_PASSWORD"
EMAIL_RECEIVER = "your.email@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465
# ==========================================
def send_discord_alert(report_text):
    """Sends the AI report to Discord."""
    # Discord has a 2000 character limit, so we truncate if necessary
    payload = {"content": f"🚨 **CRITICAL NETWORK ANOMALY DETECTED** 🚨\n\n{report_text[:1900]}"}
    requests.post(DISCORD_WEBHOOK_URL, json=payload, headers={'Content-Type': 'application/json'})
def send_email_alert(report_text):
    """Sends the AI report via Email."""
    msg = MIMEText(report_text)
    msg['Subject'] = "🚨 CRITICAL: MLSecOps Sentinel Alert"
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")
def run_sentinel():
    print(f"[{datetime.datetime.now()}] Sentinel scanning...")

    url = f"https://{WAZUH_IP}:9201/wazuh-alerts-*/_search"
    query = {
        "size": 5000,
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.groups": "fortigate"}},
                    {"range": {"timestamp": {"gte": "now-5m", "lte": "now"}}}
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}]
    }

    try:
        response = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS), headers={'Content-Type': 'application/json'}, data=json.dumps(query), verify=False)

        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            if len(hits) < 10:
                print("Minimal traffic. Sleeping.")
                return

            df = pd.json_normalize([hit['_source'] for hit in hits])
            port_col, src_col = 'data.dstport', 'data.srcport'

            if port_col in df.columns and src_col in df.columns:
                df_clean = df.dropna(subset=[port_col, src_col]).copy()
                df_clean[port_col] = pd.to_numeric(df_clean[port_col], errors='coerce')
                df_clean[src_col] = pd.to_numeric(df_clean[src_col], errors='coerce')
                df_clean = df_clean.dropna(subset=[port_col, src_col])

                # TWEAK 1: Lower contamination to 1% (Extreme Outliers Only)
                model = IsolationForest(contamination=0.01, random_state=42)
                df_clean['Anomaly_Score'] = model.fit_predict(df_clean[[port_col, src_col]])
                anomalies = df_clean[df_clean['Anomaly_Score'] == -1]

                # TWEAK 2: Only wake up Gemini/Discord if we see more than 20 anomalies
                if len(anomalies) > 20:
                    print(f"🚨 MAJOR INCIDENT: {len(anomalies)} anomalies detected. Alerting!")

                    target_ip = anomalies.iloc[0].get('data.srcip', 'Unknown')
                    alert_payload = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "ai_model": "Sentinel Isolation Forest (Headless)",
                        "alert_type": "Autonomous Network Anomaly Detection",
                        "target_host_ip": target_ip,
                        "anomalous_connections_count": len(anomalies),
                        "total_connections_scanned": len(df_clean)
                    }

                    client = genai.Client(api_key=GEMINI_API_KEY)
                    prompt = f"Analyze this network anomaly. Timestamp: {alert_payload['timestamp']}. Details: {json.dumps(alert_payload)}"
                    gen_response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)

                    send_discord_alert(gen_response.text)
                    send_email_alert(gen_response.text)
                else:
                    # Log the findings locally but stay quiet on Discord
                    print(f"ℹ️ Low-level noise: {len(anomalies)} anomalies found (Below Threshold of 20). Staying silent.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run_sentinel()
