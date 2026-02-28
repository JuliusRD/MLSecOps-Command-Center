import requests
import pandas as pd
import numpy as np
import json
import urllib3
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# Disable strict SSL warnings for our lab
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# ⚙️ CONFIGURATION
# ==========================================
WAZUH_IP = "192.168.56.10"
WAZUH_USER = "admin"
WAZUH_PASS = "YOUR_WAZUH_PASSWORD"

# ==========================================
# 📡 STEP 1: FETCH DATA (The OpenSearch JSON)
# ==========================================
def fetch_behavioral_data():
    print("📡 Step 1: Fetching 24h of network telemetry from OpenSearch...")
    url = f"https://{WAZUH_IP}:9201/wazuh-alerts-*/_search"

    # HERE IS THE OPENSEARCH JSON QUERY!
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

    response = requests.get(url, auth=(WAZUH_USER, WAZUH_PASS),
                            headers={'Content-Type': 'application/json'},
                            data=json.dumps(query), verify=False)

    if response.status_code == 200:
        hits = response.json()['hits']['hits']
        if not hits:
            return None
        return pd.json_normalize([hit['_source'] for hit in hits])
    else:
        print(f"❌ Failed to connect to OpenSearch. Code: {response.status_code}")
        return None

# ==========================================
# 🧠 STEP 2: FEATURE ENGINEERING
# ==========================================
def engineer_features(df):
    print("🧠 Step 2: Engineering Behavioral Profiles per IP...")

    # Clean the data
    df['data.sentbyte'] = pd.to_numeric(df['data.sentbyte'], errors='coerce').fillna(0)
    df['data.dstport'] = pd.to_numeric(df['data.dstport'], errors='coerce').fillna(0)

    # Group by Source IP to build the 'User' profile
    ueba_df = df.groupby('data.srcip').agg({
        'data.app': 'nunique',           # How many different apps do they use?
        'data.sentbyte': 'sum',          # How much total data are they sending?
        'data.dstport': 'mean'           # What is their 'average' destination port?
    }).reset_index()

    ueba_df.columns = ['IP', 'App_Diversity', 'Total_Upload', 'Avg_Port']
    return ueba_df

# ==========================================
# 🤖 STEP 3: K-MEANS CLUSTERING
# ==========================================
def detect_anomalies(ueba_df):
    print("🤖 Step 3: Running K-Means Clustering to find Outliers...")
    features = ueba_df[['App_Diversity', 'Total_Upload', 'Avg_Port']]

    # Scale the data (K-Means requires all numbers to be on a similar scale)
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    # Group the laptops into 2 clusters (e.g., Normal Office Workers vs. Heavy Data Users)
    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    ueba_df['Cluster'] = kmeans.fit_predict(scaled_features)

    # Calculate the distance of every laptop to its cluster's center
    distances = []
    for i, row in enumerate(scaled_features):
        cluster_center = kmeans.cluster_centers_[ueba_df['Cluster'].iloc[i]]
        # Calculate Euclidean Distance
        dist = np.linalg.norm(row - cluster_center)
        distances.append(dist)

    ueba_df['Distance'] = distances

    # Define an anomaly as any laptop in the top 5% furthest distances
    threshold = ueba_df['Distance'].quantile(0.95)
    ueba_df['Is_Anomaly'] = ueba_df['Distance'] > threshold

    return ueba_df, threshold

# ==========================================
# 🚀 MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    raw_data = fetch_behavioral_data()

    if raw_data is not None and not raw_data.empty:
        profile_df = engineer_features(raw_data)

        if len(profile_df) > 2: # We need at least 3 IPs to do clustering!
            final_df, threshold = detect_anomalies(profile_df)

            print(f"\n✅ Analysis Complete! Distance Anomaly Threshold: {threshold:.2f}")
            print("\n--- 🚨 COMPROMISED / ANOMALOUS LAPTOPS 🚨 ---")

            # Show only the anomalies
            anomalies = final_df[final_df['Is_Anomaly'] == True]

            if anomalies.empty:
                print("No anomalous behavior detected. All laptops are acting normally.")
            else:
                print(anomalies.to_string(index=False))
        else:
            print("Not enough unique IP addresses to perform clustering. Need at least 3.")
    else:
        print("No data found in OpenSearch for the last 24 hours.")