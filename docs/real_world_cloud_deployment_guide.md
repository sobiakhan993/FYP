# Real-World Cloud Production Deployment Guide

**Project Title:** Real-Time Ransomware and Poisoning Attack Detection in Cloud Environment Using Machine Learning  
**Institution:** Dawood University of Engineering & Technology (DUET), Karachi  
**Department:** Department of Cybersecurity, Faculty of Information & Computing Sciences  
**Supervisor:** Sir Arfan Naich  
**Group Members:** Sofia Naseem (23F-BSCY-40), Sobia Khan (23F-BSCY-54), Hiba Siddiqui (23F-BSCY-56)  
**Binary PDF Artifact:** [Real_World_Cloud_Deployment_Guide.pdf](file:///d:/FYP1/docs/Real_World_Cloud_Deployment_Guide.pdf)  

---

## 1. Executive Overview: Transitioning from Prototype to Production
The prototype developed in FYDP Phases 1 through 10 establishes a dual-engine detection architecture combining supervised classification (Random Forest) with unsupervised anomaly scoring (Isolation Forest) and an upstream data poisoning defense gate. 

To transition this system into an enterprise-grade cloud security product (e.g., AWS, Microsoft Azure, Google Cloud Platform), the architecture must scale across hundreds of virtual instances, interface with distributed storage buckets, ingest real operational telemetry, and execute automated active containment.

---

## 2. Real-World Telemetry Agent Architecture

### A. Host Workload Telemetry (Virtual Machines & Containers)
- **Lightweight Python Daemon (`systemd` / Windows Service):** The collector engineered in Phase 5 (`src/monitoring/host_collector.py`) can be compiled into a standalone background service running with least-privilege permissions. It hooks filesystem writes, calculates Shannon Entropy ($E > 7.5$), and captures CPU/disk I/O with less than 2% processor utilization.
- **Linux eBPF (Extended Berkeley Packet Filter):** For high-throughput cloud environments, eBPF programs trace kernel-level system calls (`sys_enter_write`, `vfs_write`) without modifying kernel source, ensuring near-zero overhead and immunity to user-space tampering.
- **Microsoft Sysmon (Windows Server Instances):** Captures Event ID 11 (FileCreate), Event ID 2 (File creation time changes), and process tree anomalies, feeding directly into the ingestion queue.

### B. Cloud-Native Storage & Management Plane (S3, Blob, Audit Logs)
- **AWS CloudTrail & Azure Activity Logs:** Monitors management plane API calls, detecting unauthorized snapshot deletion, backup purge attempts, and IAM credential compromise.
- **Amazon EventBridge & S3 Event Notifications:** Tracks bulk object alterations or mass deletions within Amazon S3 or Azure Blob Storage, triggering the feature extraction pipeline when suspicious modification rates occur.

---

## 3. Real-World Model Training & Dataset Engineering

To achieve state-of-the-art generalization in commercial cloud environments, model training must advance from synthetic datasets to real-world operational distributions:

1. **3-to-5 Day Normal Baseline Collection:** Deploy the collector daemon across staging cloud servers running genuine enterprise workloads (e.g., Nginx web servers, PostgreSQL databases, CI/CD runners). This captures authentic baseline entropy (~3.5 bits/byte), diurnal modification cycles, and routine backup archiving, establishing a clean baseline that eliminates false positives.
2. **Integrating Public Malware Corpora:** Incorporate dynamic execution traces from recognized academic benchmarks including the **UGRansome Dataset** (Locky, Cerber, WannaCry traces), **RanSMAP** (API dynamic call logs), and **CIC-IDS2017**.
3. **Safe Detonation via Automated Sandboxes:** Rather than executing live malware on internal networks, subscribe to automated analysis sandboxes (e.g. **Hybrid-Analysis**, **Any.Run**, or private Cuckoo Sandboxes). Download behavioral JSON execution reports for emerging ransomware variants (e.g. LockBit 3.0, BlackCat) and translate their disk I/O metrics into our standard 10-feature vector format.

---

## 4. Scalable Centralized Streaming Pipeline (Multi-Instance Ingestion)

Commercial deployments cannot rely on local inter-process pipes. When monitoring dozens or hundreds of cloud instances simultaneously, telemetry must flow through a resilient, decoupled message broker:

```text
[ VM-01 Agent ] ──┐
[ VM-02 Agent ] ──┼──► [ AWS SQS / Apache Kafka / Redis Streams ] ──► [ Central ML Detector API ]
[ S3 Buckets  ] ──┘                                                               │
                                                                                  ▼
                                                                     [ SecOps Web Dashboard ]
```

- **Message Broker:** Amazon SQS (Simple Queue Service) or Apache Kafka / Redis Streams.
- **Batch Consumer:** Window consumer processes 60-second sliding windows.
- **Dual-Engine Inference Engine:** Random Forest + Isolation Forest (Inference Latency < 35 ms).

---

## 5. Automated Incident Response & Active Containment (SOAR)

In production environments, passive alerting is insufficient because ransomware can encrypt thousands of files before a human analyst responds. The system must execute automated micro-containment:

1. **Immediate Network Isolation via Cloud SDKs:** Upon receiving a CRITICAL alert from the Score Combiner ($P_{rf} > 0.85$), the platform executes an automated API call using the cloud SDK (e.g. `boto3` for AWS). It re-associates the affected EC2 instance with an isolated "Quarantine" Security Group, severing all ingress/egress network connections and halting lateral malware spread.
2. **Automated EBS Snapshot Preservation:** Instantly triggers an AWS EBS Volume snapshot. This preserves cryptographic evidence, memory state, and original files for subsequent forensic decryption analysis.
3. **Multi-Channel Notification Dispatch:** Emits high-priority webhooks to corporate Slack security channels, PagerDuty incident queues, and SMS/Email alerts via Amazon SNS.

---

## 6. Continuous Upstream Poisoning Defense in Staging

To protect continuous model retraining in production against adversarial manipulation (label-flipping or clean-label backdoors):

- **Air-Gapped Staging Retraining Pipeline:** Never retrain production models directly on unverified live streams. Incoming telemetry must accumulate in an isolated staging database.
- **Multi-Stage Defensive Sanitization:** Execute the Phase 7 sanitizer module. Run $k$-NN neighborhood consistency checks ($k=5$) and Local Outlier Factor (LOF) spatial density filtering. Flagged anomalous records are routed to the `quarantine_store` database table for SecOps audit.
- **Automated Hold-Out Validation Regression Gate:** The candidate retrained model is evaluated against a locked, golden validation partition (`trusted_validation.csv`). If the validation F1-score falls below 95% or degrades by more than 2% ($\Delta F_1 > 0.02$), deployment is automatically blocked and an administrative security alert is raised.

---

## 7. Actionable Implementation Checklist for Cloud Production

| Step # | Production Action | Target Tool / Technology | Key Security Outcome |
|---|---|---|---|
| **1** | Host Agent Packaging | Linux `systemd` daemon / eBPF / Sysmon | Continuous low-overhead VM telemetry |
| **2** | Object Storage Hooks | AWS EventBridge & CloudTrail | Detects mass S3 bucket encryption |
| **3** | Central Event Broker | Amazon SQS / Apache Kafka / Redis | Scalable multi-VM stream buffering |
| **4** | Real Baseline Profiling | 3-5 Day Staging EC2 Recording | Establishes authentic zero-FPR profile |
| **5** | Active Containment | AWS Boto3 API Security Groups | Instant automatic network quarantine |
| **6** | Retraining Gate | $k$-NN + LOF + Validation Gate | Guarantees model self-protection |
