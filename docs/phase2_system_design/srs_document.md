# Software Requirements Specification (SRS)
## Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning

**Institution:** Dawood University of Engineering & Technology, Karachi  
**Department:** Department of Cybersecurity, Faculty of Information & Computing Sciences  
**Document Version:** 1.0  
**Status:** Approved for Implementation  
**Project Group:** Sofia Naseem (23F-BSCY-40), Sobia Khan (23F-BSCY-54), Hiba Siddiqui (23F-BSCY-56)  
**Supervisor:** Sir Arfan Naich  

---

## 1. Introduction

### 1.1 Purpose
This Software Requirements Specification (SRS) document provides a rigorous, comprehensive definition of the software requirements for the "Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning" system. It establishes the functional, behavioral, performance, and security requirements to guide system implementation and verification.

### 1.2 Scope of the System
The system is an end-to-end, real-time cloud security monitoring platform designed to operate within cloud infrastructure (e.g., AWS, Azure, GCP, or a localized virtualized testbed). It performs three core security functions:
1. Continuous collection and aggregation of host workload telemetry (file activity, Shannon entropy, process execution, disk I/O) and cloud audit logs.
2. Real-time classification of behavioral patterns using a dual-engine architecture combining supervised machine learning (Random Forest / XGBoost) with unsupervised anomaly detection (Isolation Forest).
3. Upstream protection of the machine learning retraining pipeline against adversarial training data poisoning (label-flipping and backdoor sample injection) via multi-stage data sanitization, outlier filtering, and trusted validation set regression gating.

### 1.3 Intended Audience and Stakeholders
- **Security Operations Center (SOC) Administrators:** Responsible for platform oversight, model retraining authorization, user access governance, and quarantine disposition.
- **Incident Response / Security Analysts:** Responsible for reviewing real-time alerts, investigating suspicious file and process anomalies, and exporting forensic attack reports.
- **Academic Review Committee & Supervisor:** Responsible for evaluating project compliance against BS Cybersecurity FYDP-1 and FYDP-2 criteria.

---

## 2. Overall Description

### 2.1 User Personas and System Actors
- **Actor 1: SOC Administrator (`admin`):**
  - Full system privileges.
  - Configures alert thresholds and notification destinations (Email, Slack, Telegram).
  - Triggers or approves model retraining workflows.
  - Reviews and manages the Poisoning Quarantine Store (releases false positives or permanently purges poisoned samples).
  - Manages analyst accounts and role-based access control (RBAC).
- **Actor 2: Security Analyst (`analyst`):**
  - Read/investigate privileges.
  - Monitors the real-time activity stream and interactive security dashboard.
  - Acknowledges, triages, and closes generated security alerts.
  - Inspects SHAP explainability insights and feature importance metrics for active alerts.
  - Exports filtered forensic reports in PDF and CSV formats.
- **Actor 3: Telemetry Collector Daemon (`collector_agent`):**
  - System background process operating on monitored virtual instances.
  - Hooks filesystem events, calculates windowed Shannon entropy, tracks process I/O, and pushes serialized telemetry events to the ingestion buffer.

### 2.2 System Operating Context
The system interfaces with:
- Monitored Cloud VMs / Container Nodes emitting file events and system metrics.
- Relational Database (PostgreSQL / SQLite) storing raw events, computed windowed features, alerts, attack logs, quarantined samples, and audit trails.
- Model Inference Engine executing low-latency feature evaluations.
- Web Application Dashboard accessible over HTTPS via standard web browsers.

---

## 3. Functional Requirements (FR-1 to FR-12)

The system satisfies the functional requirements defined in the project charter:

| Requirement ID | Requirement Statement | Priority | Module |
|---|---|---|---|
| **FR-1** | The system **must** continuously collect file events (create, modify, rename, delete), process telemetry (CPU, memory, disk I/O), and cloud activity metrics. | **Must** | Cloud Monitoring Module |
| **FR-2** | The system **must** clean, normalize, deduplicate, align timestamps, and store raw collected event data in structured relational tables. | **Must** | Data Collection Module |
| **FR-3** | The system **must** extract and aggregate behavioral features over sliding time windows (e.g., 60-second intervals), including file modification rates, Shannon entropy variations, extension alteration counts, and I/O ratios. | **Must** | Feature Engineering Pipeline |
| **FR-4** | The system **must** classify windowed activity feature vectors as normal, ransomware, or suspicious utilizing a trained, validated machine learning model. | **Must** | ML Detection Engine |
| **FR-5** | The system **must** inspect incoming training data prior to model retraining, identify poisoned samples (label-flipped or injected backdoor instances), and automatically isolate them into a Quarantine Store with detailed audit logs. | **Must** | Poisoning Detection Module |
| **FR-6** | The system **must** generate real-time security alerts categorized by severity levels (Low, Medium, High, Critical), specifying the affected resource, confidence score, and timestamp within seconds of event occurrence. | **Must** | Alert System |
| **FR-7** | The system **must** log every detected attack incident into an immutable attack log containing timestamp, attack type, source identifier, confidence level, and affected resource paths. | **Must** | Attack Logging Engine |
| **FR-8** | The system **must** provide a responsive web dashboard displaying live event metrics, recent alerts, attack history, model performance metrics, and poisoning quarantine status. | **Must** | Web Dashboard |
| **FR-9** | The system **should** automatically produce downloadable forensic and compliance reports in PDF and CSV formats covering user-specified time periods. | **Should** | Reporting Module |
| **FR-10** | The system **should** detect unknown, zero-day anomalous behaviors using an unsupervised anomaly detector (e.g., Isolation Forest) operating in parallel with the supervised classifier. | **Should** | ML Detection Engine |
| **FR-11** | The system **should** authenticate users using secure credentials and enforce Role-Based Access Control (RBAC) distinguishing Administrator and Analyst roles. | **Should** | Security & Auth Service |
| **FR-12** | The system **should** support containerized deployment (via Docker and Docker Compose) to enable portable execution across local workstations and cloud providers. | **Should** | Deployment Architecture |

---

## 4. Use Case Specifications

### Use Case UC-1: Real-Time Ransomware Detection and Alerting
- **Primary Actor:** Telemetry Collector Daemon & Security Analyst
- **Preconditions:** Collector daemon is active on the monitored virtual host; detection engine is loaded with validated model weights.
- **Main Flow:**
  1. Ransomware simulation script commences bulk encryption on target directory.
  2. Collector daemon records rapid file modifications, calculates Shannon entropy ($E > 7.5$), and detects extension alterations.
  3. Feature extractor aggregates metrics into a 60-second window feature vector.
  4. ML Detection Engine scores the feature vector: supervised classifier predicts ransomware with 98% confidence; anomaly detector flags high outlier score.
  5. Score Combiner computes composite threat score and designates alert severity as **Critical**.
  6. Alert is dispatched to the database, published to the live dashboard, and logged in the immutable attack log.
  7. Analyst views alert, reviews top contributing features, and initiates containment.

### Use Case UC-2: Training Data Poisoning Defense & Quarantine
- **Primary Actor:** SOC Administrator & Poisoning Detection Engine
- **Preconditions:** New batch of historical telemetry has been submitted for periodic model retraining.
- **Main Flow:**
  1. Administrator triggers model retraining workflow.
  2. The Poisoning Detection Engine intercepts the incoming candidate dataset.
  3. Multi-stage sanitization runs:
     - Spatial Outlier Check (Local Outlier Factor / Isolation Forest).
     - Label Consistency Check ($k$-NN voting agreement).
     - Validation Loss Regression Check.
  4. Manipulated samples (e.g., 10% label-flipped records) fail the neighborhood consistency check.
  5. Flagged samples are routed to the Quarantine Store with reason code `ERR_LABEL_FLIP_SUSPECTED`.
  6. A Poisoning Report is generated summarizing sanitized vs. quarantined sample counts.
  7. Cleaned data proceeds to model retraining; newly trained model is evaluated against the trusted validation set.
  8. If validation F1-score meets the >95% threshold, the new model is promoted to production; otherwise, deployment is blocked.

### Use Case UC-3: Exporting Forensic Incident Reports
- **Primary Actor:** Security Analyst
- **Main Flow:**
  1. Analyst navigates to the Reports tab on the web dashboard.
  2. Analyst selects date range and filters by severity (e.g., Critical and High).
  3. System queries the Attack Log and Alert database.
  4. System formats data into a structured CSV download or compiles an executive summary PDF.
  5. Analyst downloads the artifact for incident debriefing.

---

## 5. Non-Functional Requirements (NFRs)

### 5.1 Performance Requirements
- **NFR-1 (Detection Latency):** Time from event occurrence on the monitored VM to alert rendering on the dashboard shall not exceed **5.0 seconds** under standard operating conditions.
- **NFR-2 (Inference Throughput):** Machine learning model inference shall execute in **under 200 milliseconds** per sliding-window feature batch.
- **NFR-3 (Resource Footprint):** The client telemetry daemon shall consume less than **3% CPU utilization** and fewer than **100 MB RAM** on the host instance.

### 5.2 Accuracy Requirements
- **NFR-4 (Model Precision & Recall):** The supervised ransomware classifier shall achieve an F1-score of **at least 95.0%** on benchmark evaluation splits.
- **NFR-5 (False Positive Rate):** The false alarm rate during benign high-volume operations (large backups, compression archives) shall remain **below 5.0%**.
- **NFR-6 (Poisoning Defense Efficacy):** The poisoning detection module shall flag and quarantine at least **85.0% of poisoned samples** at a 10% injection rate.

### 5.3 Security and Governance Requirements
- **NFR-7 (Data Protection):** All telemetry transmitted over external networks shall utilize TLS 1.3 encryption. Passwords must be hashed using Argon2 or BCrypt with individual salts.
- **NFR-8 (Privacy Preservation):** The monitoring daemon shall record file metadata, modification counts, and entropy statistics only; no confidential file contents or cleartext payloads shall be captured or stored.
- **NFR-9 (Audit Immutability):** Attack logs and quarantine records shall maintain sequential tamper-evident logging.
