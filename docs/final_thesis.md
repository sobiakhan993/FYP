# Final Year Design Project (FYDP) Thesis

# Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning

**Department of Cybersecurity**  
**Faculty of Information & Computing Sciences**  
**Dawood University of Engineering & Technology, Karachi, Pakistan**  

---

### Project Metadata & Committee Endorsements
- **Program & Session:** Bachelor of Science in Cybersecurity (23 Fall)
- **Project Type:** Research & Development (ML Model Training + Working Real-Time Monitoring Prototype)
- **Supervisor:** Sir Arfan Naich
- **Group Members:**
  - Sofia Naseem (Roll No: 23F-BSCY-40)
  - Sobia Khan (Roll No: 23F-BSCY-54)
  - Hiba Siddiqui (Roll No: 23F-BSCY-56)
- **Academic Year:** 2026 – 2027

---

## Abstract
Cloud computing has become the backbone of modern digital enterprises, hosting mission-critical databases, shared file repositories, and elastic compute workloads. However, cloud environments face two acute, interconnected cyber threats: **cryptographic ransomware**, which automates the high-speed encryption of distributed cloud storage volumes, and **adversarial training data poisoning**, which silently corrupts the decision boundaries of machine learning (ML) threat detectors during periodic model retraining. Traditional security controls fail against both threats: signature-based antivirus cannot prevent novel zero-day ransomware bursts, while conventional intrusion monitors remain blind to mathematical poisoning of training telemetry. 

This thesis presents the design, theoretical formulation, implementation, and empirical evaluation of a unified, self-protecting cloud security platform. The system integrates three foundational components: (1) a real-time host and cloud telemetry pipeline capturing file operations, Shannon entropy dynamics ($E > 7.5$ bits/byte), process metrics, and disk I/O over sliding 60-second time windows; (2) a dual-engine machine learning detection engine combining a supervised Random Forest classifier with an unsupervised Isolation Forest anomaly detector, unified through an intelligent score combiner and SHAP feature attribution; and (3) an upstream data poisoning defense and sanitization module that evaluates $k$-Nearest Neighbors ($k$-NN) label consistency and Local Outlier Factor (LOF) spatial density to isolate manipulated records into an immutable Quarantine Store prior to retraining, verified by a trusted hold-out validation regression gate.

Extensive experimental evaluation on a curated cloud workload telemetry dataset of 5,000 samples demonstrates that our dual-engine classifier achieves a 100.0% F1-score with 0.0% false positive rate on clean held-out test data, significantly outperforming traditional rule-based heuristic detectors which produced an unacceptable 16.38% false positive rate (86 false alarms on routine compression backups). Under a 10% label-flipping poisoning attack that caused unprotected models to miss up to 22 live ransomware campaigns, our defensive sanitizer successfully filtered corrupted samples, restored validation F1-score to 0.9933, and automatically gated deployment. With sub-35 millisecond end-to-end inference latency, an interactive glassmorphic SecOps web dashboard, and automated forensic reporting, the system demonstrates the practical viability of autonomous, self-protecting threat defense for enterprise cloud infrastructures.

---

## Chapter 1: Introduction and Problem Definition

### 1.1 Motivation and Context
Cloud computing environments managed by providers such as Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP) provide unmatched elasticity and scalability. However, shared multi-tenant infrastructure, pervasive programmatic REST APIs, and automated synchronization mechanisms have drastically broadened the enterprise attack surface. In cloud storage repositories (e.g., AWS S3, Azure Blob, NFS mounts), a single compromised client or virtual machine instance can propagate cryptographic destruction across an entire enterprise within seconds.

Simultaneously, the defensive paradigm has shifted from manual rule sets toward artificial intelligence and machine learning. To maintain threat detection fidelity across shifting baseline patterns (concept drift), Security Operations Centers (SOCs) continuously harvest cloud telemetry to retrain their detection models. This operational reliance on continuous retraining creates an exploitable attack surface: an adversary who successfully injects crafted or mislabeled telemetry into cloud logs can quietly poison the model. The compromised model develops blind spots, failing to alert on real attacks while functioning normally on benign activity.

### 1.2 Problem Statement
Existing cybersecurity defenses suffer from severe fragmentation:
1. **Siloed Threat Responses:** Ransomware detectors focus exclusively on host file modifications and I/O rates, presuming that detection models are immune to compromise. Conversely, adversarial machine learning research focuses on theoretical poisoning proofs in synthetic computer vision or spam domains, rarely applying these defensive mechanisms to streaming cloud telemetry.
2. **Offline Batch Benchmarks:** Academic literature predominantly evaluates ransomware models on static, pre-packaged CSV datasets. Real cloud environments require sub-second streaming inference on sliding time-window features.
3. **Detector Retraining Vulnerability:** Unprotected automated retraining pipelines allow adversaries to manipulate classifier decision boundaries, resulting in catastrophic false negatives.
4. **False Alarm Fatigue:** Unsupervised anomaly detectors or simplistic rule-based monitors trigger frequent false alarms during benign high-volume operations (e.g., database archiving, 7-Zip compression).

### 1.3 Project Objectives and Measurable Targets
The overarching objective is to architect, build, and empirically validate a unified, real-time threat detection and poisoning mitigation platform for cloud environments.
- **Objective 1:** Engineer a lightweight streaming telemetry agent that monitors file system events, calculates Shannon entropy, and tracks process disk I/O.
- **Objective 2:** Construct a dual-engine ML detector combining supervised pattern recognition with unsupervised zero-day anomaly detection.
- **Objective 3:** Implement an upstream training data poisoning sanitization gate utilizing $k$-NN consistency and LOF spatial density checks, backed by hold-out validation regression gating.
- **Objective 4:** Provide an enterprise-grade SecOps dashboard for real-time visualization, alert triage, quarantine inspection, and forensic compliance export.
- **Measurable Benchmarks:** Detection F1-score $\ge 95\%$, False Positive Rate $< 5\%$, and Alert Latency $< 5.0$ seconds.

---

## Chapter 2: Literature Review and Research Gap

A systematic literature review was conducted analyzing 32 peer-reviewed academic works categorized across three interconnected themes:

### 2.1 Theme 1: Cloud & Host Ransomware Detection Mechanisms
Early ransomware research focused on static binary disassembling [11]. However, runtime packers and polymorphic obfuscation rendered static analysis ineffective. Research pivoted toward dynamic behavioral indicators, notably Shannon entropy calculation and filesystem heuristics [1], [2]. EldeRan [3] applied regularized Logistic Regression to dynamic API traces, achieving 96.34% accuracy. CloudRanger [6] analyzed hypervisor disk I/O using deep recurrent LSTMs. However, existing dynamic systems either require intrusive OS kernel drivers [2] or incur severe sequence observation delays [9].

### 2.2 Theme 2: Adversarial Machine Learning and Poisoning Defenses
Biggio et al. [13] first proved gradient-based poisoning attacks against Support Vector Machines. Shafahi et al. [15] introduced "Poison Frogs!", establishing that clean-label attacks can bypass superficial label filters. Severi et al. [19] showed that explanation frameworks (such as SHAP values) can be exploited to construct targeted malware backdoors. Defenses such as $k$-NN label-sanitization [17] and activation clustering [16] demonstrated promise in offline experiments, but had not been integrated into continuous cloud retraining pipelines.

### 2.3 Theme 3: Cloud Telemetry and Real-Time Streaming Defenses
Studies such as Chiba et al. [25] demonstrated real-time Random Forest classification of AWS CloudTrail logs. Pour and Injadat [26] evaluated incremental stream learning (Hoeffding Trees), but highlighted that online learners are extraordinarily susceptible to poisoning drift. Kitsune [27] utilized an ensemble of autoencoders for streaming packet anomalies, but pure anomaly detection is vulnerable to false alarms during high-volume benign bursts [28].

### 2.4 Research Gap and System Novelty
The critical literature gap is the absence of an operational architecture that protects both the cloud workload and the machine learning detector itself within a single pipeline. Our system resolves this gap by coupling a dual-engine detector with an upstream data sanitization and model regression gate.

---

## Chapter 3: Software Requirements Specification (SRS)

### 3.1 Functional Requirements (FR-1 to FR-12)
- **FR-1:** Continuous capture of file operations (create, modify, rename, delete) and process telemetry.
- **FR-2:** Deduplication, normalization, and relational persistence of raw events.
- **FR-3:** Feature extraction over 60-second sliding windows (entropy, modification rate, rename rate, I/O bandwidth).
- **FR-4:** Machine learning classification of sliding-window feature vectors.
- **FR-5:** Upstream inspection of candidate retraining data, isolating poisoned samples into a Quarantine Store.
- **FR-6:** Real-time alert generation categorized by severity (Low, Medium, High, Critical).
- **FR-7:** Immutable sequential logging of detected attack incidents.
- **FR-8:** Responsive web dashboard providing live telemetry charts, alert triage, and quarantine audit logs.
- **FR-9:** Automated export of forensic compliance reports in CSV and JSON formats.
- **FR-10:** Parallel unsupervised anomaly detection to capture novel zero-day behaviors.
- **FR-11:** Role-Based Access Control (RBAC) distinguishing Administrator and Analyst roles.
- **FR-12:** Containerized deployment support via Docker and Docker Compose.

### 3.2 Non-Functional Requirements (NFRs)
- **Performance:** End-to-end alert dispatch latency $< 5.0$ seconds; model inference latency $< 200$ ms.
- **Accuracy:** Detection F1-score $\ge 95\%$; false positive rate during benign backup compression $< 5\%$.
- **Security & Privacy:** Passwords hashed with secure salts; file metadata and entropy recorded without cleartext payloads.

---

## Chapter 4: System Architecture and Formal Design

### 4.1 Decomposed Architecture
The architecture consists of six decoupled tiers:
1. **Cloud Monitoring Agent:** Hooks filesystem events using `watchdog` and monitors host CPU/disk I/O using `psutil`.
2. **Data Collection & Ingestion Pipeline:** Implements a sliding-window aggregation consumer that aligns timestamps, calculates per-minute rates, and constructs structured feature vectors.
3. **Dual-Engine ML Detection Engine:** Evaluates feature vectors using a supervised Random Forest and an unsupervised Isolation Forest.
4. **Poisoning Detection & Quarantine Module:** Intercepts incoming retraining batches, performs $k$-NN consistency and LOF spatial checks, and enforces validation regression gating.
5. **Alert & Incident Logging System:** Categorizes threat severity and writes immutable forensic logs.
6. **SecOps Web Dashboard:** Single Page Application (SPA) providing real-time telemetry streaming via Chart.js, alert acknowledgment controls, and report generation.

---

## Chapter 5: Data Engineering & Safe Sandbox Simulation

### 5.1 Behavioral Feature Formulation
Ten features were formulated to capture the cryptographic ransomware signature:
1. `files_modified_rate` (files / minute)
2. `files_renamed_rate` (files / minute)
3. `files_deleted_rate` (files / minute)
4. `mean_entropy` (Shannon entropy in bits/byte, range $[0.0, 8.0]$)
5. `max_entropy` (Peak entropy in window)
6. `extension_changes` (Count of mass file extension alterations)
7. `disk_read_bytes_sec` (Read throughput in bytes/second)
8. `disk_write_bytes_sec` (Write throughput in bytes/second)
9. `cpu_percent` (Host CPU utilization percentage)
10. `network_bytes_sec` (Network transmission bandwidth)

### 5.2 Anti-Leakage Preprocessing
To strictly prevent data leakage:
- Raw dataset of 5,000 samples (70% Benign, 30% Ransomware) was partitioned into Train (70% = 3,500), Validation (15% = 750), and Test (15% = 750) sets using stratified sampling with a fixed random seed.
- `StandardScaler` was fitted exclusively on the training partition and serialized.

### 5.3 Harmless Isolated Sandbox Simulator
To ensure absolute testing safety without deploying malware, a dedicated sandbox simulator (`src/monitoring/sandbox_simulator.py`) was constructed in an isolated directory (`data/sandbox/dummy_drive/`). It benchmarks benign operations (entropy $\approx 3.5$) and mimics high-speed ransomware encryption by generating cryptographic pseudorandom bytes ($E > 7.9$) and appending `.locked` extensions.

---

## Chapter 6: Machine Learning Implementation

### 6.1 Supervised Random Forest Classifier
Tuned with 150 estimators, max depth of 14, and 5-fold stratified cross-validation. Feature importance analysis revealed that Shannon entropy, extension change counts, and rename rates accounted for over 85% of total predictive power.

### 6.2 Unsupervised Isolation Forest
Trained exclusively on benign workload profiles to establish normal operational baselines. Evaluates path length to isolate anomalous feature vectors without requiring labeled attack samples.

### 6.3 Hybrid Score Combiner
Combines supervised probability $P_{rf}$ and normalized anomaly score $S_{iso}$:
$$C_t = \max(P_{rf}, 0.75 \cdot S_{iso})$$
Ensures high confidence on recognized ransomware patterns while catching zero-day anomalies.

---

## Chapter 7: Poisoning Defense and Retraining Gating

### 7.1 Defensive Sanitization Pipeline
1. **$k$-NN Label-Consistency Voting:** Queries $k=5$ nearest neighbors. Samples with agreement ratio $\alpha(x_i) < 0.40$ are flagged as label-flips.
2. **Local Outlier Factor (LOF):** Isolates spatial density anomalies and crafted backdoor points.
3. **Quarantine Store:** Flagged samples are routed to a dedicated relational database table with full audit telemetry.
4. **Hold-out Validation Regression Gate:** Retrained candidate models are evaluated against the locked validation partition. If validation F1 degrades by more than 2% ($\Delta F_1 > 0.02$), deployment is blocked.

---

## Chapter 8: Experimental Evaluation & Results

### 8.1 Clean Benchmark Results
On the held-out test split (750 samples), Random Forest, Gradient Boosting, and Logistic Regression achieved 100.0% accuracy and an F1-score of 1.0000 with 0.0% false alarms. The unsupervised Isolation Forest achieved 100.0% attack recall (F1 = 0.8911) without having observed a single attack sample during training.

### 8.2 Poisoning Impact vs Defensive Recovery
- **Unprotected Retraining on 10% Poisoned Data:** Gradient Boosting recall plunged to 90.22%, missing 22 live attacks.
- **Protected Retraining with Sanitizer:** Caught 82.29% of poisoned samples at 5% poisoning, restoring validation F1 to 1.0000 (`APPROVED_FOR_DEPLOYMENT`). At 10% poisoning, restored validation F1 to 0.9933 (`APPROVED_FOR_DEPLOYMENT`). At 20% extreme poisoning, the validation regression gate immediately blocked deployment (`BLOCKED_DUE_TO_REGRESSION`).

### 8.3 Machine Learning vs Rule-Based Detection
A comparative benchmark against heuristic rules (Alert if entropy $> 6.8$ or modify rate $> 35$) showed:
- **Rule-Based Heuristic:** Accuracy = 88.53%, False Positive Rate = **16.38% (86 False Alarms)**.
- **Dual-Engine ML System:** Accuracy = **100.0%**, False Positive Rate = **0.00% (0 False Alarms)**.
Machine learning eliminates alert fatigue by distinguishing high-entropy compression from ransomware.

### 8.4 Conclusion and Future Work
This project demonstrates that coupling real-time behavioral telemetry with an upstream poisoning defense gate provides effective, robust cloud workload security. Future work will explore extending feature extraction to eBPF kernel tracing and federated cross-cloud collaborative threat intelligence.
