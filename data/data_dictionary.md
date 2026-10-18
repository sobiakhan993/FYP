# Data Dictionary and Feature Specification

This document provides a comprehensive data dictionary for all features engineered and analyzed in the **Cloud Ransomware and Poisoning Attack Detection System**.

---

## 1. Feature Specifications

| Feature Name | Data Type | Range | Units | Aggregation Window | Description & Security Relevance |
|---|---|---|---|---|---|
| `files_modified_rate` | Float | $[0.0, 500.0]$ | files / minute | 60 seconds | Number of distinct file modification events observed per minute. High values indicate mass encryption or batch updates. |
| `files_renamed_rate` | Float | $[0.0, 300.0]$ | files / minute | 60 seconds | Number of file renaming events per minute. Ransomware characteristically renames hundreds of files to append ransomware extensions (e.g. `.locked`). |
| `files_deleted_rate` | Float | $[0.0, 200.0]$ | files / minute | 60 seconds | Number of file deletion operations per minute. Ransomware or wipers frequently delete shadow copies, database backups, and system restore points. |
| `mean_entropy` | Float | $[0.0, 8.0]$ | bits / byte | 60 seconds | Average Shannon Entropy of written files. Unencrypted plain-text or structured files typically score between $2.0 - 5.5$. Encrypted ciphertexts exhibit high entropy ($> 7.5$). |
| `max_entropy` | Float | $[0.0, 8.0]$ | bits / byte | 60 seconds | Maximum observed Shannon Entropy within the time window. Serves as a sensitive trigger when individual high-value targets are encrypted. |
| `extension_changes` | Integer | $[0, 500]$ | count / window | 60 seconds | Count of anomalous extension alterations observed within the window. Normal workloads rarely alter extensions in bulk. |
| `disk_read_bytes_sec`| Float | $[0.0, 10^8]$ | bytes / second | 60 seconds | Volume of raw data read from storage devices. In ransomware execution, high read throughput occurs as the malware reads target files into memory. |
| `disk_write_bytes_sec`| Float | $[0.0, 10^8]$ | bytes / second | 60 seconds | Volume of data written to disk. Heavy write volume paired with elevated entropy indicates cipher block writes. |
| `cpu_percent` | Float | $[0.0, 100.0]$ | percent (%) | 60 seconds | Processor utilization percentage of active host processes. Cryptographic symmetric cipher loops typically spike CPU usage above 70%. |
| `network_bytes_sec` | Float | $[0.0, 10^7]$ | bytes / second | 60 seconds | Outbound and inbound network transmission throughput. Captures C2 communications, key negotiation, or pre-encryption data exfiltration. |
| `label` | Integer | $\{0, 1\}$ | class | N/A | Target classification label: `0` denotes Benign Workload; `1` denotes Malicious Ransomware Activity. |

---

## 2. Dataset Split and Statistics

- **Raw Dataset Size:** 5,000 samples (`data/raw/cloud_ransomware_raw.csv`)
  - Benign Workloads: 3,500 samples (70.0%)
  - Ransomware Attacks: 1,500 samples (30.0%)
- **Data Splits (Clean 70 / 15 / 15 Stratified Split):**
  - **Training Set (`data/processed/train.csv`):** 3,500 samples (2,450 Benign, 1,050 Attack)
  - **Validation Set (`data/processed/val.csv`):** 750 samples (525 Benign, 225 Attack)
  - **Test Set (`data/processed/test.csv`):** 750 samples (525 Benign, 225 Attack)
  - **Trusted Hold-out Validation (`data/processed/trusted_validation.csv`):** 750 samples
- **Poisoning Datasets (`data/poisoned/`):**
  - Clean Ground Truth: 3,500 samples
  - 5% Label Flipped: 175 samples inverted
  - 10% Label Flipped: 350 samples inverted
  - 20% Label Flipped: 700 samples inverted
  - 10% Injected Backdoor: 350 crafted attack points injected with benign labels
