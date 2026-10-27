# FYDP Supervisor Meeting & Review Log

**Project Title:** Real-Time Detection and Mitigation of Data Poisoning Attacks on Continuously Retrained Cloud Intrusion Detection Systems  
**Institution:** Dawood University of Engineering & Technology, Karachi  
**Department:** Department of Cybersecurity, BS Cybersecurity (Session 23 Fall)  
**Supervisor:** Sir Arfan Naich  
**Team Members:** Sofia Naseem (23F-BSCY-40), Sobia Khan (23F-BSCY-54), Hiba Siddiqui (23F-BSCY-56)

---

## Meeting Records

### Meeting 1: Scope Realignment & Ransomware Removal
- **Date:** October 2026
- **Attendees:** Sir Arfan Naich, Sofia Naseem, Sobia Khan, Hiba Siddiqui
- **Decisions & Guidance:**
  - Strictly remove ransomware detection and file entropy scanning from the project scope.
  - Re-align project squarely on **Adversarial Machine Learning (AML)**: Real-time detection and mitigation of training data poisoning attacks on continuously retrained Cloud Intrusion Detection Systems (IDS).
  - Adopt a multi-layer defense strategy (Layer A: Statistical, Layer B: Label Consistency, Layer C: Model Loss Disparity).
  - Enforce an isolated Trusted Validation Gate to prevent degraded or compromised candidate models from replacing production models.
- **Action Items:**
  - Restructure repository per approved FYDP architecture.
  - Implement clean network telemetry data generator and anti-leakage splitting pipeline.
  - Build reproducible attack simulator for label flipping and sample injection (5%, 10%, 20%).
- **Status:** Completed.

### Meeting 2: Defense Architecture & Baseline Demonstration
- **Date:** Scheduled FYDP-I Milestone Checkpoint
- **Objective:** Demonstrate clean baseline model, initial 10% label flipping degradation, multi-layer quarantine routing, and validation gate blocking.
- **Deliverables:** Working demonstration, baseline results table, and unit test reports.
