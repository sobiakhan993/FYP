# Database Schema Specification

This document defines the physical relational database schema for the **Real-Time Ransomware and Poisoning Attack Detection System**. The schema is compatible with both PostgreSQL and SQLite.

---

## 1. Relational Table Definitions (DDL)

```sql
-- 1. USERS & RBAC TABLE
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'analyst', -- 'admin' or 'analyst'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. RAW HOST & CLOUD EVENTS TABLE
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(32) NOT NULL, -- 'create', 'modify', 'rename', 'delete'
    file_path TEXT NOT NULL,
    file_extension VARCHAR(32),
    entropy REAL NOT NULL DEFAULT 0.0,
    file_size INTEGER NOT NULL DEFAULT 0,
    process_name VARCHAR(128),
    process_id INTEGER,
    source_host VARCHAR(64) DEFAULT 'cloud-vm-01'
);

-- Indexing for fast time-window querying
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

-- 3. COMPUTED SLIDING-WINDOW FEATURES TABLE
CREATE TABLE IF NOT EXISTS features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start TIMESTAMP NOT NULL,
    window_end TIMESTAMP NOT NULL,
    files_modified_rate REAL NOT NULL, -- files/min
    files_renamed_rate REAL NOT NULL,   -- files/min
    files_deleted_rate REAL NOT NULL,   -- files/min
    mean_entropy REAL NOT NULL,
    max_entropy REAL NOT NULL,
    extension_changes INTEGER NOT NULL,
    disk_read_bytes_sec REAL NOT NULL,
    disk_write_bytes_sec REAL NOT NULL,
    cpu_percent REAL NOT NULL,
    true_label VARCHAR(32) DEFAULT 'unknown' -- 'benign', 'ransomware', 'unknown'
);

CREATE INDEX IF NOT EXISTS idx_features_window ON features(window_start, window_end);

-- 4. REAL-TIME DETECTIONS & ALERTS TABLE
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id VARCHAR(64) UNIQUE NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(32) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    threat_type VARCHAR(64) NOT NULL, -- 'ransomware', 'unknown_anomaly', 'poisoning'
    confidence_score REAL NOT NULL,
    anomaly_score REAL NOT NULL,
    affected_resource TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'active', -- 'active', 'acknowledged', 'resolved'
    feature_id INTEGER,
    details_json TEXT,
    FOREIGN KEY(feature_id) REFERENCES features(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

-- 5. IMMUTABLE ATTACK LOG TABLE
CREATE TABLE IF NOT EXISTS attack_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_id VARCHAR(64) UNIQUE NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attack_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence REAL NOT NULL,
    source_ip VARCHAR(64) DEFAULT '10.0.0.4',
    affected_resource TEXT NOT NULL,
    top_signals TEXT, -- JSON array of contributing features
    mitigation_status VARCHAR(64) DEFAULT 'Alert Dispatched'
);

CREATE INDEX IF NOT EXISTS idx_attack_log_time ON attack_log(detected_at);

-- 6. MODEL REGISTRY TABLE
CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name VARCHAR(64) NOT NULL,
    model_version VARCHAR(32) NOT NULL,
    model_type VARCHAR(64) NOT NULL, -- 'classifier', 'anomaly_detector', 'score_combiner'
    f1_score REAL,
    accuracy REAL,
    false_positive_rate REAL,
    storage_path TEXT NOT NULL,
    is_active BOOLEAN DEFAULT 0,
    trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. POISONING AUDIT REPORTS TABLE
CREATE TABLE IF NOT EXISTS poisoning_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id VARCHAR(64) UNIQUE NOT NULL,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_samples_inspected INTEGER NOT NULL,
    poisoned_samples_detected INTEGER NOT NULL,
    detection_rate_pct REAL NOT NULL,
    baseline_val_accuracy REAL NOT NULL,
    retrained_val_accuracy REAL NOT NULL,
    status VARCHAR(64) NOT NULL -- 'approved', 'blocked_due_to_regression'
);

-- 8. QUARANTINE STORE TABLE
CREATE TABLE IF NOT EXISTS quarantine_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantine_id VARCHAR(64) UNIQUE NOT NULL,
    quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sample_index INTEGER NOT NULL,
    reason_code VARCHAR(64) NOT NULL, -- 'KNN_DISAGREEMENT', 'LOF_OUTLIER', 'SUSPICIOUS_FLIP'
    outlier_score REAL,
    knn_agreement REAL,
    feature_values_json TEXT NOT NULL,
    disposition VARCHAR(32) DEFAULT 'quarantined', -- 'quarantined', 'reviewed_clean', 'purged'
    report_id INTEGER,
    FOREIGN KEY(report_id) REFERENCES poisoning_reports(id)
);
```

---

## 2. Default Seed Data
The database initialization script populates:
1. Default Administrative User: `admin` (Role: `admin`)
2. Default Analyst User: `analyst` (Role: `analyst`)
3. Initial baseline model registration metadata entries.
