# REST API Specification (OpenAPI Compatible)

The REST API serves as the communication interface between the monitoring daemon, the dual ML detection engine, the poisoning sanitization pipeline, and the SecOps dashboard.

---

## 1. Authentication & System Endpoints

### 1.1 `POST /api/auth/login`
- **Description:** Authenticates security personnel and returns a session / JWT token.
- **Request Body:**
```json
{
  "username": "analyst",
  "password": "Password123!"
}
```
- **Response (200 OK):**
```json
{
  "status": "success",
  "token": "eyJhbGciOiJIUzI1NiIsIn...",
  "role": "analyst",
  "username": "analyst"
}
```

### 1.2 `GET /api/system/status`
- **Description:** Returns the overall health status of the monitoring agent, ingestion pipeline, ML models, and database.
- **Response (200 OK):**
```json
{
  "status": "healthy",
  "active_model_version": "v1.0.0",
  "agent_connected": true,
  "queue_depth": 0,
  "total_events_processed": 14205,
  "active_alerts_count": 2,
  "system_uptime_seconds": 3600
}
```

---

## 2. Telemetry Ingestion & Scoring Endpoints

### 2.1 `POST /api/events/ingest`
- **Description:** Ingests raw telemetry events from the monitored cloud VM / container.
- **Request Body:**
```json
{
  "events": [
    {
      "event_type": "modify",
      "file_path": "/var/data/finance/q3_report.xlsx",
      "file_extension": ".xlsx",
      "entropy": 7.94,
      "file_size": 1048576,
      "process_name": "python.exe",
      "process_id": 4812,
      "source_host": "cloud-vm-01"
    }
  ]
}
```
- **Response (201 Created):**
```json
{
  "status": "ingested",
  "count": 1
}
```

### 2.2 `POST /api/inference/score`
- **Description:** Evaluates a windowed feature vector against the dual-engine ML detector.
- **Request Body:**
```json
{
  "files_modified_rate": 84.5,
  "files_renamed_rate": 62.0,
  "files_deleted_rate": 12.0,
  "mean_entropy": 7.82,
  "max_entropy": 7.98,
  "extension_changes": 65,
  "disk_read_bytes_sec": 4500000.0,
  "disk_write_bytes_sec": 12000000.0,
  "cpu_percent": 88.4
}
```
- **Response (200 OK):**
```json
{
  "verdict": "ransomware",
  "confidence_score": 0.985,
  "anomaly_score": -0.42,
  "threat_level": "critical",
  "top_signals": [
    {"feature": "max_entropy", "value": 7.98, "contribution": "high"},
    {"feature": "files_modified_rate", "value": 84.5, "contribution": "high"},
    {"feature": "extension_changes", "value": 65, "contribution": "high"}
  ],
  "alert_generated": true,
  "alert_id": "ALT-20261018-842"
}
```

---

## 3. Alerts & Incident Management Endpoints

### 3.1 `GET /api/alerts`
- **Description:** Lists real-time security alerts with filtering options (severity, status, date).
- **Query Parameters:** `severity=critical,high`, `status=active`, `limit=50`
- **Response (200 OK):**
```json
{
  "total": 3,
  "alerts": [
    {
      "alert_id": "ALT-20261018-842",
      "timestamp": "2026-10-18T12:15:30Z",
      "severity": "critical",
      "threat_type": "ransomware",
      "confidence_score": 0.985,
      "affected_resource": "/var/data/finance/",
      "status": "active"
    }
  ]
}
```

### 3.2 `POST /api/alerts/{alert_id}/acknowledge`
- **Description:** Changes alert status to `acknowledged` or `resolved`.
- **Response (200 OK):**
```json
{
  "alert_id": "ALT-20261018-842",
  "status": "acknowledged",
  "analyst": "analyst"
}
```

### 3.3 `GET /api/attacks/log`
- **Description:** Returns the immutable historical attack log for forensic review.
- **Response (200 OK):**
```json
{
  "records": [
    {
      "attack_id": "ATK-9901",
      "detected_at": "2026-10-18T12:15:30Z",
      "attack_type": "ransomware",
      "severity": "critical",
      "confidence": 0.985,
      "source_ip": "10.0.0.4",
      "affected_resource": "/var/data/finance/",
      "mitigation_status": "Alert Dispatched"
    }
  ]
}
```

---

## 4. Poisoning Defense & Model Retraining Endpoints

### 4.1 `POST /api/poisoning/sanitize-and-retrain`
- **Description:** Ingests candidate training dataset, executes k-NN & LOF outlier checks, quarantines corrupted records, and validates retrained model performance against the hold-out validation set.
- **Request Body:**
```json
{
  "dataset_path": "data/processed/candidate_batch_02.csv",
  "auto_quarantine": true,
  "validation_regression_tolerance": 0.03
}
```
- **Response (200 OK):**
```json
{
  "report_id": "REP-POI-2026-004",
  "total_samples": 1000,
  "poisoned_samples_flagged": 98,
  "detection_rate_pct": 98.0,
  "quarantine_status": "98 samples isolated into quarantine_store",
  "baseline_val_f1": 0.978,
  "retrained_val_f1": 0.975,
  "deployment_status": "approved",
  "promoted_model_version": "v1.1.0"
}
```

### 4.2 `GET /api/poisoning/quarantine`
- **Description:** Fetches all quarantined samples with their rejection reasons and scores.
- **Response (200 OK):**
```json
{
  "quarantined_samples": [
    {
      "quarantine_id": "QRN-441",
      "quarantined_at": "2026-10-18T12:20:00Z",
      "reason_code": "KNN_DISAGREEMENT",
      "outlier_score": 2.45,
      "knn_agreement": 0.20,
      "disposition": "quarantined"
    }
  ]
}
```

---

## 5. Reporting Endpoints

### 5.1 `GET /api/reports/export?format=csv`
- **Description:** Streams a consolidated CSV forensic report of all detected attacks and alerts.
- **Response:** `Content-Type: text/csv`

### 5.2 `GET /api/reports/export?format=json`
- **Description:** Returns a structured summary report including system health, model telemetry, alert triage, and poisoning defense statistics.
