# System Architecture and Design Diagrams

This document contains formal design models for the **Real-Time Ransomware and Poisoning Attack Detection System**, including System Architecture, Data Flow Diagrams (Level 0 and Level 1), Entity Relationship Diagram, Use Case Diagram, and Sequence Diagrams.

---

## 1. High-Level System Architecture Diagram

```mermaid
flowchart TB
    subgraph Host["Cloud Workload / Monitored Environment"]
        Agent["Lightweight Monitoring Agent (watchdog, psutil)"]
        FS["File Operations (Create, Write, Rename, Delete)"]
        PROC["Process & I/O Telemetry (Disk R/W, CPU, RAM)"]
        FS --> Agent
        PROC --> Agent
    end

    subgraph DataPipeline["Data Ingestion & Feature Pipeline"]
        Queue["Telemetry Event Queue / Ingestion Buffer"]
        Consumer["Data Collection Consumer"]
        Cleaner["Deduplicator & Timestamp Aligner"]
        FeatureEngine["Feature Extraction Engine (Entropy, Burst Rate, R/W Ratio)"]
        
        Agent -->|JSON Telemetry Stream| Queue
        Queue --> Consumer
        Consumer --> Cleaner
        Cleaner --> FeatureEngine
    end

    subgraph Storage["Persistence Layer (PostgreSQL / SQLite)"]
        DB_Events[("events")]
        DB_Features[("features")]
        DB_Alerts[("alerts")]
        DB_Attacks[("attack_log")]
        DB_Quarantine[("quarantine_store")]
        DB_Models[("model_registry")]
    end

    Cleaner -.-> DB_Events
    FeatureEngine -.-> DB_Features

    subgraph RetrainingLoop["Upstream Retraining & Poisoning Protection"]
        NewData["Candidate Training Batches"]
        PoisonDetector["Poisoning Detection Module"]
        KNNCheck["k-NN Label Consistency"]
        LOFCheck["LOF Outlier Detector"]
        ValCheck["Trusted Validation Regression Gate"]
        QuarantineAction["Quarantine Store"]
        Trainer["Retraining Pipeline"]

        NewData --> PoisonDetector
        PoisonDetector --> KNNCheck
        PoisonDetector --> LOFCheck
        KNNCheck -->|Flagged| QuarantineAction
        LOFCheck -->|Flagged| QuarantineAction
        QuarantineAction --> DB_Quarantine
        
        KNNCheck -->|Sanitized Clean Data| Trainer
        LOFCheck -->|Sanitized Clean Data| Trainer
        Trainer --> ValCheck
        ValCheck -->|Accuracy >= 95%| DB_Models
        ValCheck -->|Regression Detected| BlockDeployment["Block Deployment & Alert"]
    end

    subgraph InferenceEngine["Dual-Engine Real-Time ML Detector"]
        FeatureRow["Sliding-Window Feature Vector"]
        Supervised["Supervised Classifier (Random Forest / XGBoost)"]
        Anomaly["Unsupervised Anomaly Detector (Isolation Forest)"]
        Combiner["Score Combiner & Decision Logic"]
        Explainability["SHAP Explainability Insights"]

        FeatureEngine --> FeatureRow
        DB_Models -.->|Active Weights| Supervised
        DB_Models -.->|Baseline Profile| Anomaly
        FeatureRow --> Supervised
        FeatureRow --> Anomaly
        Supervised --> Combiner
        Anomaly --> Combiner
        Combiner --> Explainability
    end

    subgraph Alerting["Alert & Notification Engine"]
        AlertRouter["Severity Classifier (Low / Medium / High / Critical)"]
        Dedup["De-duplication & Throttling Window"]
        Notifier["Dispatchers (Webhooks, Dashboard SSE/WebSocket)"]

        Combiner -->|Threat Score > Threshold| AlertRouter
        AlertRouter --> Dedup
        Dedup --> DB_Alerts
        Dedup --> DB_Attacks
        Dedup --> Notifier
    end

    subgraph Presentation["SecOps Web Dashboard & API"]
        API["FastAPI / Flask Application Server"]
        UI["Interactive SecOps Web Dashboard"]
        Reports["PDF / CSV Forensic Report Generator"]

        API --> DB_Alerts
        API --> DB_Attacks
        API --> DB_Quarantine
        Notifier --> UI
        UI --> API
        UI --> Reports
    end
```

---

## 2. Data Flow Diagrams (DFD)

### 2.1 Level-0 DFD (Context Diagram)

```mermaid
flowchart LR
    VM["Monitored Cloud Virtual Machine"] -->|Raw System & File Events| System(("Cloud Ransomware & Poisoning Detection Platform"))
    Admin["SOC Administrator"] -->|Retraining Trigger & Config| System
    Analyst["Security Analyst"] -->|Query Alerts & Investigations| System
    
    System -->|Real-Time Alerts & Severity Status| Analyst
    System -->|Forensic PDF/CSV Reports| Analyst
    System -->|Poisoning Audit & Retraining Report| Admin
    System -->|Quarantine Statistics| Admin
```

### 2.2 Level-1 DFD (Decomposed Subsystems)

```mermaid
flowchart TD
    VM["Monitored VM"] -->|1. Raw File & Process Events| P1["1.0 Cloud Monitoring & Event Capture"]
    P1 -->|2. Event Stream| P2["2.0 Ingestion & Feature Engineering"]
    
    P2 -->|3. Raw Events| D1[("D1: Raw Events")]
    P2 -->|4. 60-Sec Feature Vectors| D2[("D2: Feature Store")]
    P2 -->|5. Live Feature Vector| P3["3.0 Dual-Engine Inference Service"]

    D3[("D3: Model Registry")] -->|6. Validated Model Artifacts| P3
    P3 -->|7. Predictions & Anomaly Scores| P4["4.0 Alert & Attack Logging Engine"]
    
    P4 -->|8. Incident Record| D4[("D4: Attack Log")]
    P4 -->|9. Security Alerts| D5[("D5: Alerts Store")]
    P4 -->|10. Dispatch Alert| Analyst["Security Analyst Dashboard"]

    Admin["SOC Administrator"] -->|11. Ingest Batch for Retraining| P5["5.0 Poisoning Detection & Sanitization"]
    P5 -->|12. Flagged Corrupted Data| D6[("D6: Quarantine Store")]
    P5 -->|13. Sanitized Verified Data| P6["6.0 Model Retraining & Validation Gate"]
    P6 -->|14. Verified Candidate Model| D3
```

---

## 3. Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    USERS ||--o{ ATTACK_LOG : investigates
    USERS ||--o{ ALERTS : acknowledges
    USERS {
        int id PK
        string username
        string password_hash
        string role "admin | analyst"
        datetime created_at
    }

    EVENTS ||--o{ FEATURES : aggregates_into
    EVENTS {
        int id PK
        string event_id
        datetime timestamp
        string event_type "create|modify|rename|delete"
        string file_path
        string file_extension
        float entropy
        int file_size
        string process_name
        int process_id
    }

    FEATURES ||--o{ ALERTS : triggers
    FEATURES {
        int id PK
        datetime window_start
        datetime window_end
        float files_modified_rate
        float files_renamed_rate
        float files_deleted_rate
        float mean_entropy
        float max_entropy
        int extension_changes
        float disk_read_bytes_sec
        float disk_write_bytes_sec
        float cpu_percent
        string true_label "benign | ransomware"
    }

    ALERTS ||--|| ATTACK_LOG : records
    ALERTS {
        int id PK
        string alert_id
        datetime timestamp
        string severity "low | medium | high | critical"
        float confidence_score
        float anomaly_score
        string affected_resource
        string status "active | acknowledged | resolved"
        int feature_id FK
    }

    ATTACK_LOG {
        int id PK
        string attack_id
        datetime detected_at
        string attack_type "ransomware | data_poisoning | zero_day_anomaly"
        float confidence
        string details_json
        string source_ip
    }

    POISONING_REPORTS ||--o{ QUARANTINE_STORE : documents
    POISONING_REPORTS {
        int id PK
        datetime analyzed_at
        int total_samples_inspected
        int poisoned_samples_detected
        float detection_rate_pct
        float baseline_val_accuracy
        float retrained_val_accuracy
        string status "approved | blocked_due_to_regression"
    }

    QUARANTINE_STORE {
        int id PK
        datetime quarantined_at
        string sample_id
        string reason_code
        float outlier_score
        int knn_agreement_count
        string feature_values_json
        string disposition "quarantined | released | purged"
        int report_id FK
    }

    MODELS {
        int id PK
        string model_name
        string model_version
        string model_type "classifier | anomaly_detector"
        float f1_score
        float accuracy
        float false_positive_rate
        string storage_path
        boolean is_active
        datetime trained_at
    }
```

---

## 4. Sequence Diagrams

### 4.1 Sequence Diagram: Real-Time Ransomware Detection and Alerting

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Ransomware Simulator
    participant VM as Monitored VM (Watchdog/Psutil)
    participant Pipe as Feature Pipeline
    participant ML as Dual ML Engine
    participant AlertEng as Alert & Attack Logger
    participant DB as System Database
    actor Analyst as Analyst Dashboard

    Attacker->>VM: Encrypts 50 files & appends .locked
    VM->>VM: Calculates Shannon Entropy (E = 7.92)
    VM->>Pipe: Push raw events (Path, Entropy, Extension, I/O)
    Pipe->>Pipe: Window aggregations (60s feature vector)
    Pipe->>ML: Evaluate feature vector
    ML->>ML: RF Classifier score = 0.985 (Ransomware)
    ML->>ML: Isolation Forest score = -0.42 (Anomaly)
    ML->>ML: Score Combiner designates composite threat = 0.99
    ML->>AlertEng: Emit detection result (Critical Threat)
    AlertEng->>DB: Store Alert record & Attack Log entry
    AlertEng->>Analyst: Push real-time alert (WebSocket / SSE)
    Analyst->>Analyst: Triage alert, view SHAP attribution, isolate VM
```

### 4.2 Sequence Diagram: Training Data Poisoning Defense & Retraining Gating

```mermaid
sequenceDiagram
    autonumber
    actor Admin as SOC Administrator
    participant RetrainMgr as Retraining Orchestrator
    participant Sanitizer as Poisoning Detection Module
    participant QuarStore as Quarantine Store
    participant Trainer as Model Trainer
    participant ValGate as Trusted Validation Gate
    participant Registry as Model Registry

    Admin->>RetrainMgr: Ingest candidate retraining dataset
    RetrainMgr->>Sanitizer: Validate dataset for poisoning attacks
    Sanitizer->>Sanitizer: Run k-NN label consistency check (k=5)
    Sanitizer->>Sanitizer: Run Local Outlier Factor (LOF) spatial check
    alt Corrupted Samples Detected
        Sanitizer->>QuarStore: Quarantine flagged samples (Log reason & metrics)
        Sanitizer->>RetrainMgr: Return sanitized clean training subset
    end
    RetrainMgr->>Trainer: Train candidate model on sanitized data
    Trainer->>ValGate: Evaluate candidate model on clean hold-out set
    alt Validation Accuracy >= 95% & Regression < 2%
        ValGate->>Registry: Register model as active production version v(N+1)
        ValGate->>Admin: Retraining successful notification
    else Regression > 2% (Poisoning Contamination Breached)
        ValGate->>Admin: Block deployment! Raise Critical Poisoning Alert
    end
```

---

## 5. Use Case Diagram

```mermaid
flowchart LR
    subgraph Actors
        Admin((SOC Admin))
        Analyst((Security Analyst))
        SystemDaemon((Monitoring Agent))
    end

    subgraph SystemBoundary["Cloud Threat Detection Platform"]
        UC1([UC-1: Stream Host & Cloud Telemetry])
        UC2([UC-2: Detect Ransomware in Real-Time])
        UC3([UC-3: View Live Alerts & System Health])
        UC4([UC-4: Inspect SHAP Feature Importance])
        UC5([UC-5: Ingest Retraining Data])
        UC6([UC-6: Sanitize & Quarantine Poisoned Data])
        UC7([UC-7: Evaluate Model Validation Gate])
        UC8([UC-8: Export PDF/CSV Incident Reports])
        UC9([UC-9: Manage User Roles & Permissions])
    end

    SystemDaemon --> UC1
    UC1 --> UC2
    UC2 --> UC3
    Analyst --> UC3
    Analyst --> UC4
    Analyst --> UC8
    Admin --> UC5
    UC5 --> UC6
    UC6 --> UC7
    Admin --> UC9
```
