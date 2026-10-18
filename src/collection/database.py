"""
Database Layer for Real-Time Detection Platform
Supports SQLite and PostgreSQL. Provides thread-safe schema initialization
and optimized query interfaces for events, features, alerts, attack logs,
models, and poisoning quarantine records.
"""

import os
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'cloud_security.db'))

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(64) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(32) NOT NULL DEFAULT 'analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 2. Raw Events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id VARCHAR(64) UNIQUE NOT NULL,
        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        event_type VARCHAR(32) NOT NULL,
        file_path TEXT NOT NULL,
        file_extension VARCHAR(32),
        entropy REAL NOT NULL DEFAULT 0.0,
        file_size INTEGER NOT NULL DEFAULT 0,
        process_name VARCHAR(128),
        process_id INTEGER,
        source_host VARCHAR(64) DEFAULT 'cloud-vm-01'
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")

    # 3. Sliding-Window Features
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS features (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        window_start TIMESTAMP NOT NULL,
        window_end TIMESTAMP NOT NULL,
        files_modified_rate REAL NOT NULL,
        files_renamed_rate REAL NOT NULL,
        files_deleted_rate REAL NOT NULL,
        mean_entropy REAL NOT NULL,
        max_entropy REAL NOT NULL,
        extension_changes INTEGER NOT NULL,
        disk_read_bytes_sec REAL NOT NULL,
        disk_write_bytes_sec REAL NOT NULL,
        cpu_percent REAL NOT NULL,
        network_bytes_sec REAL DEFAULT 0.0,
        true_label VARCHAR(32) DEFAULT 'unknown'
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_features_window ON features(window_start, window_end);")

    # 4. Alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id VARCHAR(64) UNIQUE NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        severity VARCHAR(32) NOT NULL,
        threat_type VARCHAR(64) NOT NULL,
        confidence_score REAL NOT NULL,
        anomaly_score REAL NOT NULL,
        affected_resource TEXT NOT NULL,
        status VARCHAR(32) DEFAULT 'active',
        feature_id INTEGER,
        details_json TEXT,
        FOREIGN KEY(feature_id) REFERENCES features(id)
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")

    # 5. Attack Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_id VARCHAR(64) UNIQUE NOT NULL,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attack_type VARCHAR(64) NOT NULL,
        severity VARCHAR(32) NOT NULL,
        confidence REAL NOT NULL,
        source_ip VARCHAR(64) DEFAULT '10.0.0.4',
        affected_resource TEXT NOT NULL,
        top_signals TEXT,
        mitigation_status VARCHAR(64) DEFAULT 'Alert Dispatched'
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_log_time ON attack_log(detected_at);")

    # 6. Model Registry
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS models (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name VARCHAR(64) NOT NULL,
        model_version VARCHAR(32) NOT NULL,
        model_type VARCHAR(64) NOT NULL,
        f1_score REAL,
        accuracy REAL,
        false_positive_rate REAL,
        storage_path TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 0,
        trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 7. Poisoning Reports
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS poisoning_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id VARCHAR(64) UNIQUE NOT NULL,
        analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_samples_inspected INTEGER NOT NULL,
        poisoned_samples_detected INTEGER NOT NULL,
        detection_rate_pct REAL NOT NULL,
        baseline_val_accuracy REAL NOT NULL,
        retrained_val_accuracy REAL NOT NULL,
        status VARCHAR(64) NOT NULL
    );
    """)

    # 8. Quarantine Store
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS quarantine_store (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        quarantine_id VARCHAR(64) UNIQUE NOT NULL,
        quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        sample_index INTEGER NOT NULL,
        reason_code VARCHAR(64) NOT NULL,
        outlier_score REAL,
        knn_agreement REAL,
        feature_values_json TEXT NOT NULL,
        disposition VARCHAR(32) DEFAULT 'quarantined',
        report_id INTEGER,
        FOREIGN KEY(report_id) REFERENCES poisoning_reports(id)
    );
    """)
    
    # Seed default admin and analyst credentials if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM users;")
    if cursor.fetchone()['cnt'] == 0:
        cursor.execute("""
        INSERT INTO users (username, password_hash, role) VALUES 
        ('admin', 'admin123', 'admin'),
        ('analyst', 'analyst123', 'analyst');
        """)
        
    conn.commit()
    conn.close()
    print(f"[+] Database schema successfully initialized at: {DB_PATH}")

# Helper CRUD operations
def insert_event(event_dict: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR IGNORE INTO events 
    (event_id, timestamp, event_type, file_path, file_extension, entropy, file_size, process_name, process_id, source_host)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_dict['event_id'],
        event_dict.get('timestamp', datetime.utcnow().isoformat()),
        event_dict['event_type'],
        event_dict['file_path'],
        event_dict.get('file_extension', ''),
        float(event_dict.get('entropy', 0.0)),
        int(event_dict.get('file_size', 0)),
        event_dict.get('process_name', 'system'),
        int(event_dict.get('process_id', 0)),
        event_dict.get('source_host', 'cloud-vm-01')
    ))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def insert_feature_row(feat_dict: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO features 
    (window_start, window_end, files_modified_rate, files_renamed_rate, files_deleted_rate,
     mean_entropy, max_entropy, extension_changes, disk_read_bytes_sec, disk_write_bytes_sec,
     cpu_percent, network_bytes_sec, true_label)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        feat_dict['window_start'], feat_dict['window_end'],
        float(feat_dict['files_modified_rate']),
        float(feat_dict['files_renamed_rate']),
        float(feat_dict['files_deleted_rate']),
        float(feat_dict['mean_entropy']),
        float(feat_dict['max_entropy']),
        int(feat_dict['extension_changes']),
        float(feat_dict['disk_read_bytes_sec']),
        float(feat_dict['disk_write_bytes_sec']),
        float(feat_dict['cpu_percent']),
        float(feat_dict.get('network_bytes_sec', 0.0)),
        feat_dict.get('true_label', 'unknown')
    ))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def insert_alert(alert_dict: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO alerts 
    (alert_id, timestamp, severity, threat_type, confidence_score, anomaly_score, affected_resource, status, feature_id, details_json)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_dict['alert_id'],
        alert_dict.get('timestamp', datetime.utcnow().isoformat()),
        alert_dict['severity'],
        alert_dict['threat_type'],
        float(alert_dict['confidence_score']),
        float(alert_dict['anomaly_score']),
        alert_dict['affected_resource'],
        alert_dict.get('status', 'active'),
        alert_dict.get('feature_id'),
        json.dumps(alert_dict.get('details_json', {}))
    ))
    alert_row_id = cursor.lastrowid
    
    # Also log into immutable attack_log
    cursor.execute("""
    INSERT INTO attack_log 
    (attack_id, detected_at, attack_type, severity, confidence, affected_resource, top_signals)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "ATK-" + alert_dict['alert_id'],
        alert_dict.get('timestamp', datetime.utcnow().isoformat()),
        alert_dict['threat_type'],
        alert_dict['severity'],
        float(alert_dict['confidence_score']),
        alert_dict['affected_resource'],
        json.dumps(alert_dict.get('details_json', {}).get('top_signals', []))
    ))
    
    conn.commit()
    conn.close()
    return alert_row_id

if __name__ == '__main__':
    init_db()
