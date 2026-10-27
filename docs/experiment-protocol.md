# Experimental Protocol & Evaluation Methodology

**Project:** Real-Time Detection and Mitigation of Data Poisoning Attacks on Continuously Retrained Cloud IDS  
**Institution:** Dawood University of Engineering & Technology, Karachi  
**Supervisor:** Sir Arfan Naich  

---

## 1. Experimental Objectives

This protocol establishes the rigorous, reproducible benchmarking procedure to evaluate:
1. **Victim Model Vulnerability:** Quantify performance degradation of the Cloud IDS under poisoning without defense across budgets of 5%, 10%, and 20%.
2. **Layered Defense Accuracy:** Measure Precision, Recall, F1-Score, and False-Quarantine Rate for:
   - Layer A (Statistical Anomaly / Isolation Forest)
   - Layer B (Label Consistency / $k$-NN Topology)
   - Layer C (Model Loss & Confidence Margin)
   - Combined Multi-Layer Defense
3. **Safe Retraining Gating:** Validate that candidate models failing on the isolated `trusted_validation.csv` holdout are blocked from promotion, and the last approved model is preserved.
4. **Processing Latency:** Record median and 95th percentile inline batch processing time.

---

## 2. Dataset & Split Governance (Zero Leakage)

- **Total Records:** 10,000 cloud network flow telemetry vectors.
- **Partitioning:**
  - `Train (70%)`: 7,000 records (clean baseline training partition).
  - `Val (15%)`: 1,500 records (used for detector threshold tuning & reference neighborhood fitting).
  - `Trusted Holdout (15%)`: 1,500 records (immutable, strictly isolated from attack scripts and threshold tuning; reserved exclusively for the Trusted Validation Gate).
- **Scaler Fitting:** `StandardScaler` fitted exclusively on the clean training partition.
- **Provenance:** SHA-256 hashes registered in `data/processed/split_manifest.json`.

---

## 3. Attack Scenarios & Budgets

| Attack Scenario | Technique | Attack Target | Poisoning Budgets | Random Seeds |
| :--- | :--- | :--- | :--- | :--- |
| **Label Flipping** | Stealth class inversion | Malicious $\to$ Benign | 5%, 10%, 20% | 42, 123, 999 |
| **Sample Injection** | Boundary perturbation ($\sigma=0.35$) | Crafted attack vectors labeled Benign | 5%, 10%, 20% | 42, 123, 999 |

*Note: Ground-truth poison flags are recorded strictly separately in `attack_manifest.json` and are NEVER accessible to detection layers during evaluation.*

---

## 4. Evaluation Metrics & Success Criteria

1. **Poison Detection Metrics:**
   $$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}, \quad F_1 = \frac{2 \cdot \text{Prec} \cdot \text{Rec}}{\text{Prec} + \text{Rec}}$$
   $$\text{False Quarantine Rate (FQR)} = \frac{FP}{FP + TN}$$

2. **Victim Model Protection Metrics:**
   - Retrained IDS F1-score with defense versus without defense.
   - Validation Gate Gating Action: `PROMOTED` vs `BLOCKED_BY_GATE`.
   - Rollback restoration success rate.
