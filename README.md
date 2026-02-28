# 🛡️ Unified MLSecOps Command Center

An end-to-end Machine Learning and Security Orchestration, Automation, and Response (SOAR) pipeline built for a custom hybrid enterprise network. This project ingests live SIEM data, applies ML for anomaly detection and UEBA, and utilizes Generative AI for automated incident triage.

## 🏗️ Architecture
This dashboard acts as the "Single Pane of Glass" for a 4-node virtualized environment:
* **SIEM:** OpenSearch & Wazuh Manager (Ubuntu)
* **Firewall Telemetry:** FortiGate UTM logs
* **Endpoint Telemetry:** Sysmon & Windows Active Directory
* **Offensive Emulation:** Kali Linux

## 🧠 Machine Learning & AI Features

### 1. Unsupervised Anomaly Detection (Isolation Forest)
* **Objective:** Detect anomalous outbound network traffic and Data Exfiltration/C2 beacons.
* **Mechanism:** Dynamically ingests live FortiGate firewall logs, extracts Destination/Source port features, and trains an `sklearn` Isolation Forest in real-time. Outliers are plotted on an interactive 2D scatter chart.

### 2. User & Entity Behavior Analytics (K-Means Clustering)
* **Objective:** Identify compromised hosts and insider threats in an AD-less environment.
* **Mechanism:** Groups network entities based on Application Diversity, Total Upload Volume, and Average Destination Port. Calculates Euclidean distance to identify endpoints acting strictly outside of normal company baseline behavior.

### 3. Live Sequence Triage (Behavioral Analysis)
* **Objective:** Identify malicious application access sequences bypassing static firewall rules.
* **Mechanism:** Queries the most recent network events for a given IP, constructing a chronological behavioral sequence (e.g., `QUIC ➔ SSL ➔ Google.Services ➔ iCloud`).

### 4. Generative AI Incident Reporting (Google Gemini)
* **Objective:** Automate Tier 1/Tier 2 SOC Analyst ticket creation.
* **Mechanism:** Ingests the behavioral payload and utilizes the `google-genai` SDK to generate a professional Incident Response report detailing the threat and immediate containment steps.

### 5. The Autonomous Sentinel (Headless SOAR)
* **Objective:** 24/7 Proactive Threat Hunting with Zero Token Waste.
* **Mechanism:** A headless Linux `systemd` cron job (`sentinel.py`) that scores live traffic every 5 minutes. If (and only if) the ML model detects an extreme outlier threshold, it wakes the GenAI model, generates the report, and pushes an alert to **Discord** and **Email**.

## 🛠️ Installation & Deployment
This application is completely stateless. No credentials or API keys are hardcoded.

1. Clone the repository:
   ```bash
   git clone https://github.com/JuliusRD/MLSecOps-Command-Center.git
   cd MLSecOps-Command-Center
   ```

2. Create and activate a Python virtual environment (Recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the interactive dashboard:
   ```bash
   streamlit run dashboard.py
   ```
5. Access the web interface at http://localhost:8501 and enter your SIEM IP, Wazuh credentials, and Gemini API key directly into the secure sidebar.

## 🤖 Running the Headless Sentinel
To run the 24/7 autonomous alerting script in the background:
```bash
python sentinel.py
```
(Note: Ensure you update the webhook URLs and email credentials inside sentinel.py before running).