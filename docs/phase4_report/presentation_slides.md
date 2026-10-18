# Phase-I Defense Presentation: Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning

**Institution:** Dawood University of Engineering & Technology, Karachi  
**Department:** Department of Cybersecurity, Faculty of Information & Computing Sciences  
**Program:** BS Cybersecurity (Session 23 Fall)  
**Supervisor:** Sir Arfan Naich  
**Presenters:** Sofia Naseem (23F-BSCY-40), Sobia Khan (23F-BSCY-54), Hiba Siddiqui (23F-BSCY-56)  

---

## Slide 1: Title and Overview
- **Project Title:** Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning
- **Context:** BS Cybersecurity Final Year Design Project (FYDP-1 Milestone)
- **Core Mission:** Design and construct a unified, real-time cloud security platform that detects high-speed cryptographic ransomware while safeguarding its own machine learning models against adversarial training data poisoning.

---

## Slide 2: Problem Statement & Motivation
- **The Cloud Dilemma:** Cloud environments house enterprise-critical databases and shared storage; however, automated synchronization spreads ransomware across attached buckets in minutes.
- **The Retraining Paradox:** Machine learning models deployed for cloud threat detection must periodically retrain on incoming telemetry.
- **The Threat:** Attackers poison incoming training logs (via label flipping or injected backdoor triggers), silently corrupting model decision boundaries.
- **The Gap:** Conventional tools either detect ransomware OR study adversarial ML on offline image datasets. No single system protects both the cloud workload and the detector's retraining pipeline in real time.

---

## Slide 3: Project Objectives & Measurable Targets
- **Primary Objectives:**
  1. Detect cloud ransomware within seconds using dynamic behavioral telemetry.
  2. Implement an upstream data poisoning sanitization gate before model retraining.
  3. Combine supervised classification with unsupervised zero-day anomaly detection.
  4. Provide an interactive SecOps dashboard with live alerts, attack logs, and reports.
- **Target Performance Benchmarks (Supervisor Approved):**
  - Detection F1-Score: $\ge 95\%$
  - False Positive Rate (FPR): $< 5\%$
  - Real-time Alert Latency: $< 5.0$ seconds

---

## Slide 4: Literature Survey & Identified Research Gap
- **Survey Breadth:** 32 peer-reviewed academic papers categorized into 3 core themes:
  - *Theme 1:* Ransomware heuristics & file entropy (CryptoLock, ShieldFS, EldeRan, CloudRanger).
  - *Theme 2:* Adversarial ML & poisoning countermeasures (Biggio, TRIM, Poison Frogs, k-NN sanitization).
  - *Theme 3:* Cloud telemetry & streaming intrusion detection (CloudTrail, Kitsune, Hoeffding Trees).
- **Core Research Gap:**
  - Traditional ransomware detectors are vulnerable to silent poisoning during retraining.
  - Poisoning defenses are rarely integrated into live streaming cloud telemetry pipelines.

---

## Slide 5: System Architecture & Workflow
- **6 Decoupled System Modules:**
  1. **Cloud Monitoring Module:** Lightweight telemetry agent (`watchdog`, `psutil`) tracking file operations, entropy, and I/O.
  2. **Data Collection Pipeline:** Ingestion buffer computing 60-second sliding-window feature vectors.
  3. **Dual-Engine ML Detection:** Supervised Random Forest/XGBoost + Unsupervised Isolation Forest.
  4. **Poisoning Detection Gate:** $k$-NN label consistency + Local Outlier Factor (LOF) spatial filtering.
  5. **Alert System:** Severity triage (Low, Medium, High, Critical) with automatic de-duplication.
  6. **SecOps Web Dashboard:** Live monitoring, SHAP feature importance, and PDF/CSV report exports.

---

## Slide 6: Requirements Specification (FR-1 to FR-12)
- **Core "Must" Requirements:**
  - Continuous telemetry collection & normalization (FR-1, FR-2)
  - Behavioral feature extraction (entropy, rename rate, I/O bursts) (FR-3)
  - Dual-engine machine learning scoring (FR-4, FR-10)
  - Upstream poisoning detection & quarantine storage (FR-5)
  - Real-time severity alerting & immutable attack logging (FR-6, FR-7)
  - Interactive SecOps dashboard (FR-8)
- **Key NFRs:** Sub-5 second alert latency, $< 200$ ms inference per batch, strict privacy (no cleartext file payload storage).

---

## Slide 7: Feature Engineering & Data Preparation
- **10 Core Behavioral Signals:**
  - `files_modified_rate`, `files_renamed_rate`, `files_deleted_rate`
  - `mean_entropy`, `max_entropy` (Shannon Entropy in bits/byte)
  - `extension_changes` (e.g. mass conversion to `.locked`)
  - `disk_read_bytes_sec`, `disk_write_bytes_sec`, `cpu_percent`, `network_bytes_sec`
- **Data Hygiene & Anti-Leakage Methodology:**
  - Curated 5,000 cloud workload samples (70% Benign, 30% Attack).
  - Split 70% Train, 15% Val, 15% Test with fixed random seed.
  - Scaler fitted *strictly* on training data only to eliminate test data leakage.

---

## Slide 8: Safe Isolated Sandbox Simulator
- **Design Philosophy:** Never deploy or execute real malware.
- **Engineered Simulator (`src/monitoring/sandbox_simulator.py`):**
  - Confined to isolated directory: `data/sandbox/dummy_drive/`
  - Populates realistic multi-directory file trees (spreadsheets, source code, documents).
  - Benign mode: Routine edits, reads, and log appends (Entropy $\approx 3.5$ bits/byte).
  - Attack mode: High-speed symmetric cipher simulation generating pseudo-random bytes (Entropy $> 7.9$ bits/byte) and appending `.locked`.
  - Emits real-time JSON telemetry stream to the feature pipeline.

---

## Slide 9: Baseline Model Results (Clean Benchmark)
- **Evaluated on Held-out Clean Test Split (750 samples):**

| Model | Accuracy | Precision | Recall | F1-Score | False Positives |
|---|:---:|:---:|:---:|:---:|:---:|
| **Logistic Regression** | 100% | 100% | 100% | **1.0000** | 0.0% |
| **Random Forest** | 100% | 100% | 100% | **1.0000** | 0.0% |
| **Gradient Boosting** | 100% | 100% | 100% | **1.0000** | 0.0% |
| **Isolation Forest (Unsupervised)** | 92.67% | 80.36% | **100%** | **0.8911** | 10.48% |

- **Key Finding:** Unsupervised Isolation Forest detected **100% of ransomware attacks** without ever seeing an attack sample in training, verifying its zero-day defense capability!

---

## Slide 10: Empirical Proof of Poisoning Vulnerability
- **The Experiment:** Retraining baseline models on 10% label-flipped training data without defense:
- **Catastrophic Impact on Security:**
  - **Random Forest:** Missed **11 live attacks** (Recall fell to 95.11%).
  - **Gradient Boosting:** Missed **22 live attacks** (Recall plunged to **90.22%**, F1 = 0.9486).
- **Conclusion:** Proves that even the strongest ML classifiers become critically compromised under mild data poisoning, establishing the absolute necessity of our Phase II Poisoning Defense Module.

---

## Slide 11: Phase II (FYDP-2) Roadmap & Milestones
- **Weeks 17 - 20 (Phase 5):** Cloud environment setup, event queue, and real-time streaming pipeline.
- **Weeks 19 - 23 (Phase 6):** Advanced ML models, score combiner, and SHAP explainability.
- **Weeks 22 - 25 (Phase 7):** Upstream poisoning defense engine ($k$-NN, LOF, quarantine store, validation gate).
- **Weeks 24 - 28 (Phase 8):** FastAPI backend, real-time WebSocket dashboard, and PDF/CSV reporting.
- **Weeks 28 - 32 (Phases 9 & 10):** Full sandbox attack simulations, load testing, final thesis, and IEEE paper.

---

## Slide 12: Conclusion & Q&A
- **Phase I Milestones Complete:**
  - Comprehensive 32-paper literature review and confirmed research gap.
  - Complete SRS and architectural design specifications.
  - Leak-free data preparation and isolated sandbox simulator.
  - Baseline models and empirical validation of poisoning vulnerability.
- **Thank you!**
- We now invite questions and feedback from our respected Supervisor and Evaluation Committee.
