# Cloud Defense Sentinel: System Operator & Analyst User Manual

**Project Title:** Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning  
**Institution:** Dawood University of Engineering & Technology, Karachi  
**Department:** Department of Cybersecurity, Faculty of Information & Computing Sciences  
**Document Version:** 1.0 (Production Release)  

---

## 1. System Requirements & Installation

### 1.1 Prerequisites
- **Operating System:** Windows 10/11 or Ubuntu Linux 22.04 LTS
- **Python Runtime:** Python 3.10+ (Tested on Python 3.13)
- **Memory & Storage:** 8 GB RAM minimum, 2 GB free disk space
- **Web Browser:** Google Chrome, Mozilla Firefox, or Microsoft Edge

### 1.2 Installation Steps
1. Navigate to the project directory:
   ```bash
   cd D:/FYP1
   ```
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database and models:
   ```bash
   python src/collection/database.py
   python src/detection/detector_engine.py
   ```

---

## 2. Starting the Platform

### 2.1 Starting the Web Dashboard & API Server
Run the Flask API backend and SecOps Dashboard:
```bash
python src/api/app.py
```
The server will bind to `http://127.0.0.1:5000`.

### 2.2 Starting the Live Host Monitoring Agent (Optional VM Telemetry)
To monitor a specific directory or cloud volume in real time:
```bash
python src/monitoring/host_collector.py data/sandbox/dummy_drive
```

---

## 3. Navigating the SecOps Web Dashboard

Access the interactive interface by opening your browser to:
```
http://127.0.0.1:5000
```

### 3.1 Default Credentials
- **Administrator Role:**
  - Username: `admin`
  - Password: `admin123`
- **Security Analyst Role:**
  - Username: `analyst`
  - Password: `analyst123`

---

## 4. Operational Workflows

### 4.1 Live Monitoring & Telemetry (Tab 1)
- **Top Metric Cards:** Continuously displays Total Telemetry Events, Active Threat Level, File Modification Rate (ops/min), and Mean Shannon Entropy.
- **Real-Time Stream Chart:** Visualizes entropy fluctuations and modification bursts over sliding time windows.
- **Threat Probability Radar:** Shows the balance between Benign, Ransomware, and Anomaly risks.
- **Live Stream Feed:** Console displaying timestamped filesystem events and detection triggers.

### 4.2 Executing Safe Attack Simulations (Tab 1 & Tab 5)
- **Launch Simulated Ransomware Attack:**
  - Click the crimson button `💥 Launch Simulated Ransomware Attack`.
  - Harmlessly encrypts dummy files in `data/sandbox/dummy_drive/` with high-entropy bytes ($E > 7.9$) and renames them to `.locked`.
  - Triggers an instant **CRITICAL RANSOMWARE ALERT** on the dashboard within 35 ms!
- **Run Benign Routine Workload:**
  - Click `📁 Run Benign Routine Workload`.
  - Simulates normal reads, appends, and low-entropy writes.
  - Confirms system remains in `NORMAL` status without false alarms.

### 4.3 Alert Triage & Acknowledgment (Tab 2)
- Security analysts can review triggered alerts, inspect the confidence score and affected resources, and click **Acknowledge** to mark alerts as investigated.

### 4.4 Upstream Retraining Poisoning Defense (Tab 4)
- **Select Retraining Batch:** Choose candidate datasets (5%, 10%, 20% label-flipped or injected backdoor batches).
- **Click `🛡️ Run Multi-Stage Sanitizer & Gate Retraining`:**
  - Inspects records via $k$-NN label consistency and Local Outlier Factor (LOF).
  - Automatically routes corrupted samples into the **Poisoning Quarantine Store**.
  - Evaluates candidate retrained model against the hold-out validation regression gate.
  - Displays whether the model passed validation (`APPROVED_FOR_DEPLOYMENT`) or was blocked (`BLOCKED_DUE_TO_REGRESSION`).

### 4.5 Forensic Compliance Reports (Tab 6)
- Click **`📥 Download Consolidated CSV Attack Log`** to obtain an audit trail of all detected attacks.
- Click **`📄 Print Executive Report Summary`** to print or export a formatted summary PDF.

---

## 5. Automated Verification & Testing

To run the complete automated test suite:
```bash
python -m unittest discover tests
```

To run the full multi-module demonstration runner:
```bash
python demo_runner.py
```
