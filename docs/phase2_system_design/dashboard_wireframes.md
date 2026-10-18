# Dashboard UI Wireframes and Layout Specifications

This document outlines the visual structure, layout components, and operational interactions for the **SecOps Live Threat Detection & Poisoning Defense Dashboard**.

---

## 1. Visual Theme and Aesthetic Guidelines
- **Theme:** Dark Cybersecurity Glassmorphism (`#0B0F19` deep navy base, `#111827` card containers, `#1F2937` borders).
- **Accent Palettes:**
  - **Normal / Healthy:** Emerald Green (`#10B981`)
  - **Suspicious / Warning:** Amber Yellow (`#F59E0B`)
  - **Critical Ransomware Threat:** Crimson Red (`#EF4444`)
  - **Poisoning Defense / Isolation:** Electric Indigo / Cyan (`#6366F1` / `#06B6D4`)
- **Typography:** Inter, Outfit, or Roboto (clean, sans-serif, high-legibility monospace for telemetry logs).

---

## 2. Global Navigation and Layout Structure

```
+----------------------------------------------------------------------------------------------------+
|  [SHIELD LOGO] CLOUD DEFENSE SENTINEL | Real-Time Ransomware & Poisoning Detection   [Live: 🟢 CONNECTED]  |
|  Logged in as: admin (Administrator)                                                  [Logout]      |
+----------------------------------------------------------------------------------------------------+
|  [ NAV TABS ]:  [📊 Live Monitoring]  [🚨 Active Alerts (3)]  [📜 Attack History]  [🛡️ Poisoning Defense]  [📑 Forensic Reports]
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Screen 1: Live Monitoring & Telemetry (Primary View)

```
+----------------------------------------------------------------------------------------------------+
| TOP METRIC CARDS:                                                                                  |
| +---------------------+ +---------------------+ +---------------------+ +----------------------+ |
| | Events Processed    | | Active Threat Level | | File Change Rate    | | Shannon Mean Entropy | |
| | 18,420 events       | | 🔴 CRITICAL ALERT   | | 84.5 files/min      | | 7.91 bits/byte       | |
| +---------------------+ +---------------------+ +---------------------+ +----------------------+ |
+----------------------------------------------------------------------------------------------------+
| CHARTS ROW:                                                                                        |
| +---------------------------------------------------+ +------------------------------------------+ |
| | Real-Time Telemetry Stream (Chart.js)             | | Dual-Engine Threat Radar                 | |
| | [Graph: File Modifications & Entropy over time]   | | [Supervised: 98% Ransomware Confidence]  | |
| |                                                   | | [Isolation Forest Anomaly Score: -0.42]  | |
| | -----------------------📈 Entropy (Max 8.0)       | | [Composite Status: 🚨 MALICIOUS BURST]   | |
| | -----------------------📊 IOPS / Modify Rate      | | [Top Signal: Shannon Entropy Spike]      | |
| +---------------------------------------------------+ +------------------------------------------+ |
+----------------------------------------------------------------------------------------------------+
| LIVE TELEMETRY LOG FEED:                                                                           |
| [12:15:02] [MODIFY] /finance/q3_ledger.xlsx | Entropy: 7.95 | Proc: encryptor.py (PID: 512)        |
| [12:15:03] [RENAME] /finance/q3_ledger.xlsx -> q3_ledger.locked                                    |
| [12:15:04] [ALERT]  🚨 Critical Ransomware Pattern detected in sliding window #892               |
+----------------------------------------------------------------------------------------------------+
```

---

## 4. Screen 2: Poisoning Defense & Quarantine Management

```
+----------------------------------------------------------------------------------------------------+
| UPSTREAM RETRAINING SECURITY GATE                                                                 |
| Candidate Retraining Batch: candidate_batch_02.csv (1,000 samples)                                |
| Baseline Clean Accuracy: 98.2% | Tolerance Window: 2.0%                                           |
+----------------------------------------------------------------------------------------------------+
| SANITIZATION SUMMARY:                                                                              |
| Total Samples Inspected: 1,000 | Flagged Poisoned: 98 (9.8%) | Sanitized Clean: 902 (90.2%)        |
| Gated Model Retrained Val Accuracy: 97.6% (Regression: 0.6% -> PASSED & DEPLOYED)                  |
+----------------------------------------------------------------------------------------------------+
| QUARANTINE STORE AUDIT TABLE:                                                                      |
| | Sample ID | Quarantined At       | Detection Method   | Disagreement Ratio | Action Taken        | |
| | QRN-001   | 2026-10-18 12:20:01  | k-NN Consistency   | 80% Neighbors Diff | [Release] [Purge]   | |
| | QRN-002   | 2026-10-18 12:20:01  | LOF Spatial Outlier| Distance Score 3.1 | [Release] [Purge]   | |
| | QRN-003   | 2026-10-18 12:20:01  | k-NN Consistency   | 100% Label Flips   | [Release] [Purge]   | |
+----------------------------------------------------------------------------------------------------+
```

---

## 5. Screen 3: Forensic Reports & Export

```
+----------------------------------------------------------------------------------------------------+
| GENERATE COMPLIANCE & INCIDENT REPORTS                                                             |
| Date Range: [2026-10-18] to [2026-10-18]  | Severity Filter: [All / High & Critical]              |
| Export Options:                                                                                    |
| [📥 Download Full CSV Report]   [📄 Export Executive PDF Summary]                                  |
+----------------------------------------------------------------------------------------------------+
```
