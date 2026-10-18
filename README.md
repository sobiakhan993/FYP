# Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-v0.1--phase1-success.svg)]()
[![Domain](https://img.shields.io/badge/domain-Cybersecurity%20%7C%20Cloud%20SecOps%20%7C%20AML-red.svg)]()

A BS Cybersecurity Final Year Design Project (FYDP) at **Dawood University of Engineering & Technology, Karachi**.

- **Faculty / Department:** Faculty of Information & Computing Sciences / Department of Cybersecurity
- **Program & Session:** BS Cybersecurity, Session 23 Fall
- **Supervisor:** Sir Arfan Naich
- **Group Members:**
  - Sofia Naseem (23F-BSCY-40)
  - Sobia Khan (23F-BSCY-54)
  - Hiba Siddiqui (23F-BSCY-56)

---

## 📖 Project Overview

This project engineers an end-to-end, real-time machine learning security platform designed to simultaneously detect **cryptographic ransomware campaigns** and **adversarial training data poisoning attacks** inside a cloud environment.

### The Problem
1. **Ransomware in Cloud:** Modern ransomware encrypts thousands of cloud files and shared buckets in minutes. Traditional signature-based antivirus cannot catch zero-day variants, while manual log reviews are too slow.
2. **Data Poisoning Vulnerability:** Threat detection models retrained periodically on fresh cloud telemetry can be quietly compromised by adversaries inserting manipulated records (label-flipping or clean-label backdoors), blinding the security system to subsequent attacks without causing software crashes.

### Our Solution
- **Dual-Engine ML Detection:** Combines a supervised behavioral classifier (Random Forest / XGBoost) for known ransomware activity with an unsupervised anomaly detector (Isolation Forest) for novel zero-day behaviors.
- **Autonomous Retraining Self-Protection:** Filters incoming training data through an upstream multi-stage Poisoning Sanitization Module ($k$-NN label consistency, Local Outlier Factor, and hold-out validation regression gating) before any model retraining is accepted.
- **Real-Time Streaming Telemetry:** Captures file system events, Shannon entropy escalation ($> 7.5$ bits/byte), process I/O, and cloud metrics within 60-second sliding windows.
- **SecOps Web Dashboard:** Visualizes live system health, severity-ranked alerts (Low, Medium, High, Critical), immutable attack logs, SHAP explainability insights, and automated PDF/CSV report exports.

---

## 📂 Repository Structure

```
d:/FYP1/
├── README.md                           # Master project documentation
├── requirements.txt                    # Python project dependencies
├── .gitignore                          # Git ignore definitions
├── docs/                               # Phase deliverables and academic reports
│   ├── phase1_literature_review/       # Phase 1: Literature Review & Gap
│   │   ├── literature_review.md        # Comprehensive 8-10 page academic review
│   │   ├── literature_matrix.md        # 28-paper comparative analysis matrix
│   │   ├── literature_matrix.csv       # Spreadsheet-compatible matrix export
│   │   └── references_ieee.md          # 32 IEEE-formatted citations
│   ├── phase2_system_design/           # Phase 2: Requirements & Architecture
│   │   ├── srs_document.md             # Formal Software Requirements Spec (FR-1 to FR-12)
│   │   ├── architecture_and_diagrams.md# Architecture, DFD L0/L1, ER, Sequence diagrams
│   │   ├── database_schema.md          # Relational SQL schema (PostgreSQL & SQLite)
│   │   ├── api_endpoints.md            # OpenAPI compatible REST API specification
│   │   ├── technology_decision_note.md # Technology selection & trade-off rationale
│   │   └── dashboard_wireframes.md     # UI layout & component wireframes
│   ├── phase3_eda/                     # Phase 3: Exploratory Data Analysis outputs
│   │   └── eda_summary_report.txt      # Descriptive statistics & feature correlations
│   └── phase4_report/                  # Phase 4: Interim Report & Evaluation
│       ├── phase1_interim_report.md    # Formal FYDP-1 interim submission report
│       ├── baseline_results.md         # Baseline evaluation & poisoning vulnerability tables
│       └── presentation_slides.md      # 12-slide Phase-I defense presentation deck
├── data/                               # Versioned data stores
│   ├── raw/                            # 5,000 raw cloud workload & ransomware samples
│   ├── processed/                      # Leak-free Train (70%), Val (15%), Test (15%) splits
│   ├── poisoned/                       # 5%, 10%, 20% label-flipped & 10% injected datasets
│   ├── sandbox/                        # Isolated dummy drive for harmless attack simulation
│   └── data_dictionary.md              # Formal dictionary describing all 10 features
├── models/                             # Serialized trained model weights
│   ├── random_forest.joblib            # Trained baseline Random Forest
│   ├── gradient_boosting.joblib        # Trained Gradient Boosting classifier
│   ├── logistic_regression.joblib      # Trained Logistic Regression baseline
│   ├── isolation_forest.joblib         # Trained unsupervised anomaly detector
│   └── scaler.joblib                   # Scaler fitted exclusively on training partition
├── notebooks/                          # Interactive analysis scripts
│   └── eda_analysis.py                 # EDA audit & feature correlation engine
├── src/                                # Core system source code
│   ├── monitoring/                     # Event & metric collectors, sandbox simulator
│   │   └── sandbox_simulator.py        # Safe harmless encryption & benign workload simulator
│   ├── collection/                     # Data ingestion, preprocessing, and splitting
│   │   ├── dataset_generator.py        # Cloud workload behavioral dataset generator
│   │   └── preprocess_data.py          # Anti-leakage preprocessing & splitting pipeline
│   ├── detection/                      # Ransomware classifiers & anomaly engines
│   │   └── baseline_models.py          # Baseline model trainer & poisoning impact evaluator
│   ├── poisoning/                      # Poisoning simulators, sanitizers, and quarantine
│   │   └── poisoning_simulator.py      # Label-flipping & crafted sample generator
│   ├── alerts/                         # Severity rules & alert dispatchers
│   ├── api/                            # REST API application server
│   └── dashboard/                      # Web dashboard frontend
└── tests/                              # Unit & integration test suites
```

---

## ⚡ Quick Start & Reproducibility Guide

### 1. Environment Setup
Clone the repository and install the dependencies:
```bash
git clone https://github.com/your-org/fyp1-cloud-detection.git
cd FYP1
pip install -r requirements.txt
```

### 2. Run Data Generation and Preprocessing (Phase 3)
Generate the 5,000-sample cloud workload dataset and split into train/val/test without data leakage:
```bash
# Generate raw dataset (3,500 benign, 1,500 attack)
python src/collection/dataset_generator.py

# Preprocess, scale, and split 70/15/15
python src/collection/preprocess_data.py

# Run Exploratory Data Analysis (EDA)
python notebooks/eda_analysis.py
```

### 3. Generate Poisoned Datasets
Create 5%, 10%, and 20% label-flipped and injected attack datasets:
```bash
python src/poisoning/poisoning_simulator.py
```

### 4. Run Baseline Experiments & Poisoning Vulnerability Test (Phase 4)
Train baseline classifiers, the unsupervised Isolation Forest, and measure the empirical accuracy/recall drop from a 10% poisoning attack:
```bash
python src/detection/baseline_models.py
```

### 5. Run the Safe Sandbox Simulator
Verify file entropy calculations and safe simulated mass encryption in an isolated test folder:
```bash
python src/monitoring/sandbox_simulator.py
```

---

## 📊 Phase-I Key Results Summary

### Clean Benchmark Results (Held-out Test Split - 750 samples)
| Model | Type | Accuracy | Precision | Recall | F1-Score | FPR |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Random Forest** | Supervised | 100.0% | 100.0% | 100.0% | **1.0000** | 0.00% |
| **Gradient Boosting** | Supervised | 100.0% | 100.0% | 100.0% | **1.0000** | 0.00% |
| **Logistic Regression** | Supervised | 100.0% | 100.0% | 100.0% | **1.0000** | 0.00% |
| **Isolation Forest** | Unsupervised | 92.67% | 80.36% | **100.0%** | **0.8911** | 10.48% |

*Zero-Day Capability:* The unsupervised Isolation Forest flagged **100% of ransomware attack bursts** without having seen a single attack sample during training.

### Poisoning Vulnerability Demonstration (10% Label-Flipping Attack)
| Model | Clean Test Recall | Poisoned Test Recall | Missed Attacks (FN) | Poisoned F1-Score |
|---|:---:|:---:|:---:|:---:|
| **Logistic Regression** | 100.0% | 95.11% | **11 attacks missed** | 0.9749 |
| **Random Forest** | 100.0% | 95.11% | **11 attacks missed** | 0.9749 |
| **Gradient Boosting** | 100.0% | 90.22% | **22 attacks missed** | **0.9486** |

*Conclusion:* Injecting 10% poisoned records directly blinded Gradient Boosting into missing 22 live ransomware attacks, establishing the critical necessity for Phase II's upstream poisoning defense module.

---

## 🚀 FYDP-2 (Phase II) Implementation Roadmap

- **Phase 5:** Cloud Test Environment & Real-Time Telemetry Pipeline (Weeks 17 to 20)
- **Phase 6:** Advanced ML Models, Hyperparameter Tuning & SHAP Explainability (Weeks 19 to 23)
- **Phase 7:** Upstream Poisoning Defense Module ($k$-NN, LOF, Quarantine Store, Validation Gate) (Weeks 22 to 25)
- **Phase 8:** System Integration, REST API, and Interactive SecOps Web Dashboard (Weeks 24 to 28)
- **Phase 9:** Comprehensive Sandbox Attack Testing, False Alarm Benchmarking, Load Tests (Weeks 28 to 30)
- **Phase 10:** Final Thesis, IEEE-Format Conference Paper, and Final Defense (Weeks 30 to 32)
