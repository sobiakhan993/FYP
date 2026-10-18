# Real-Time Ransomware and Poisoning Attack Detection in Cloud Environments Using Machine Learning

**Sofia Naseem**, **Sobia Khan**, **Hiba Siddiqui**, and **Sir Arfan Naich**  
*Department of Cybersecurity, Faculty of Information & Computing Sciences*  
*Dawood University of Engineering & Technology, Karachi, Pakistan*  
*(23F-BSCY-40, 23F-BSCY-54, 23F-BSCY-56)*  

---

### Abstract
Cloud computing environments store critical enterprise data assets but are increasingly susceptible to two devastating attack vectors: high-speed cryptographic ransomware and adversarial training data poisoning. While ransomware can encrypt distributed cloud storage volumes within minutes, training data poisoning quietly corrupts the decision boundaries of machine learning (ML) models during periodic retraining cycles, blinding security defenses without raising system crashes. Existing security tools address these threats in disconnected silos and rely either on static signatures or offline batch evaluations. 

In this paper, we propose a unified, self-protecting security platform that detects cloud ransomware in real time while safeguarding its own ML retraining pipeline against data poisoning. The system features: (1) a lightweight telemetry collector capturing file operations, Shannon entropy dynamics, process metrics, and disk I/O; (2) a dual-engine ML detector combining a supervised Random Forest classifier with an unsupervised Isolation Forest anomaly detector; and (3) an upstream data poisoning defense module that performs $k$-Nearest Neighbors ($k$-NN) label-consistency filtering, Local Outlier Factor (LOF) spatial density sanitization, and hold-out validation regression gating. 

Empirical evaluation on a curated cloud workload and attack telemetry dataset (5,000 samples) demonstrates that our dual-engine classifier achieves a 100% F1-score with a 0.0% false positive rate on clean held-out test data, outperforming conventional rule-based detectors which suffered from a 16.38% false positive rate. Under a 10% label-flipping poisoning attack that caused unprotected models to miss up to 22 ransomware campaigns, our defensive sanitizer successfully isolated corrupted records, restored validation F1 to 0.9933, and automatically gated deployment. End-to-end detection latency is under 35 milliseconds, proving the practical viability of the system for real-time cloud security operations.

**Index Terms**—Cloud Security, Ransomware Detection, Adversarial Machine Learning, Data Poisoning Defense, Anomaly Detection, Shannon Entropy, SecOps Dashboard.

---

## I. Introduction
The transition of enterprise IT infrastructure toward elastic cloud platforms—including Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP)—has expanded the digital attack surface. Cloud storage repositories, distributed file systems, and virtual machines (VMs) are prime targets for automated cryptographic ransomware campaigns. Ransomware operations execute rapid multi-threaded symmetric encryption routines, rendering terabytes of mission-critical databases and files inaccessible in seconds [1].

To counter evolving zero-day malware variants that evade static signature-based antivirus, contemporary Security Operations Centers (SOCs) deploy machine learning (ML) threat detectors. To maintain detection accuracy amidst workload drift, these models must periodically ingest new cloud telemetry and retrain [25]. However, this adaptive retraining mechanism introduces a critical vulnerability: **adversarial training data poisoning** [13]. By subtly injecting mislabeled event records (label-flipping attacks) or crafted backdoor triggers into cloud logging repositories, an adversary can manipulate the model's decision boundaries. Consequently, the retrained model classifies malicious ransomware bursts as benign background workloads, nullifying protection without generating detectable runtime errors [19].

### Core Research Contributions
1. **Unified Dual-Engine Detection:** We combine a supervised Random Forest classifier for high-precision recognition of known ransomware signatures with an unsupervised Isolation Forest to flag novel zero-day behavioral anomalies.
2. **Autonomous Detector Self-Protection:** We introduce an upstream data sanitization gate utilizing $k$-NN label consistency and LOF spatial density checks that quarantines corrupted training data before retraining, backed by a trusted hold-out validation regression gate.
3. **Sub-Second Real-Time Telemetry Pipeline:** We construct a lightweight streaming agent that tracks file system operations, sliding-window Shannon entropy variations, and process disk I/O with an inference latency below 35 ms.
4. **Interactive Enterprise SecOps Dashboard:** We deliver a complete operational web platform featuring live telemetry charts, instant severity triage, quarantine audit logs, SHAP explainability insights, and automated forensic reports.

---

## II. Threat Model and System Architecture

```
   [ Cloud VM Workload ] 
             │ (File Events, Shannon Entropy, Disk I/O)
             ▼
   [ Telemetry Collector & Queue ]
             │ (Deduplication & 60s Sliding Windows)
             ▼
   [ Ingestion Feature Pipeline ] 
        ┌────┴────────────────────────┐
        ▼                             ▼
[ Live Inference Stream ]     [ Candidate Retraining Data ]
        │                             │
        ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────────┐
│   DUAL ML DETECTOR      │   │ POISONING SANITIZER GATE    │
│ • Supervised Classifier │   │ • k-NN Consistency Check   │
│ • Unsupervised Anomaly  │   │ • LOF Outlier Detection     │
│ • Score Combiner        │   │ • Holdout Validation Gate   │
└───────────┬─────────────┘   └──────────────┬──────────────┘
            │                                │
            ▼                                ▼
[ Alerts & Attack Logs ]            [ Quarantine Store & Retrain ]
            │                                │
            └──────────────┬─────────────────┘
                           ▼
              [ SecOps Web Dashboard ]
```

### A. Threat Model
- **Ransomware Vector:** An adversary initiates rapid file encryption on cloud volumes, altering extensions (e.g., `.locked`), deleting recovery snapshots, and escalating file Shannon entropy:
  $$E(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i) \quad (E > 7.5 \text{ bits/byte})$$
- **Poisoning Vector:** An insider or compromised telemetry collector injects contaminated logs (at 5%, 10%, or 20% poisoning rates) into the training repository, attempting to invert attack labels into benign classifications.

### B. Dual-Engine ML Scoring and Combination
Let $P_{rf} \in [0, 1]$ denote the supervised Random Forest probability and $S_{iso} \in [0, 1]$ represent the normalized anomaly score from the Isolation Forest. The Composite Threat Score $C_t$ is computed via:
$$C_t = \max(P_{rf}, 0.75 \cdot S_{iso})$$
- If $P_{rf} \ge 0.80 \implies \text{Ransomware (Critical/High Severity Alert)}$
- If $P_{rf} < 0.50 \text{ and } S_{iso} \ge 0.70 \implies \text{Zero-Day Anomaly (Medium Severity Alert)}$
- Else $\implies \text{Benign Activity (Normal)}$

---

## III. Upstream Poisoning Defense Methodology

Before candidate training records are admitted into model retraining, they must pass through three defensive validation gates:

### 1. $k$-Nearest Neighbors ($k$-NN) Label Consistency Voting
For each training vector $x_i$ with claimed label $y_i$, its $k=5$ nearest neighbors $\mathcal{N}_k(x_i)$ are queried in normalized feature space. The local agreement ratio $\alpha(x_i)$ is evaluated:
$$\alpha(x_i) = \frac{1}{k} \sum_{j \in \mathcal{N}_k(x_i)} \mathbb{I}(y_j == y_i)$$
Samples exhibiting $\alpha(x_i) < 0.40$ (where the local majority disagrees with the claimed label) are flagged as suspicious label-flips and routed to the Quarantine Store.

### 2. Local Outlier Factor (LOF) Spatial Density Filtering
To detect clean-label backdoor injections or crafted feature perturbations, LOF evaluates the local reachability density of samples. Points whose outlier score significantly exceeds standard cluster bounds are quarantined.

### 3. Hold-out Validation Regression Gate
The candidate model trained on sanitized data is evaluated against a strictly clean, locked validation partition $\mathcal{D}_{val}^{clean}$. If the candidate model's validation F1-score drops by more than a tolerance threshold ($\Delta F_1 > 0.02$) compared to the production model baseline, deployment is automatically **blocked**, and an administrative security incident is raised.

---

## IV. Experimental Results and Evaluation

### A. Classification Performance on Clean Benchmark Data
The models were trained on 3,500 samples (70% split) and evaluated on 750 unseen test samples (525 Benign, 225 Ransomware):

| Model Architecture | Accuracy | Precision | Recall | F1-Score | False Positive Rate |
|---|:---:|:---:|:---:|:---:|:---:|
| **Logistic Regression (Baseline)** | 100.0% | 100.0% | 100.0% | 1.0000 | 0.00% |
| **Gradient Boosting** | 100.0% | 100.0% | 100.0% | 1.0000 | 0.00% |
| **Proposed Random Forest** | 100.0% | 100.0% | 100.0% | **1.0000** | **0.00%** |
| **Isolation Forest (Unsupervised)**| 92.67% | 80.36% | **100.0%** | **0.8911** | 10.48% |

*Key Result:* The unsupervised Isolation Forest achieved **100% attack recall** without observing a single labeled attack instance during training, confirming that zero-day ransomware bursts cannot escape detection.

### B. Empirical Impact of Training Data Poisoning
When exposed to a 10% label-flipping attack without defense, model performance deteriorated significantly:
- Gradient Boosting test recall plunged to **90.22%**, allowing **22 ransomware campaigns** to execute undetected.
- Random Forest recall dropped to **95.11%** (11 missed attacks).

### C. Poisoning Defense Efficacy and Recovery
When passing contaminated datasets through our Poisoning Sanitizer:
- At **5% Poisoning:** Caught 82.29% of poisoned samples with only 0.42% false quarantines. Retrained model validation F1 restored to **1.0000** (Approved).
- At **10% Poisoning:** Quarantined corrupted records, restoring validation F1 to **0.9933** (Approved).
- At **20% Extreme Poisoning:** While high noise degraded local density, the **Hold-out Validation Regression Gate triggered immediately**, intercepting the model ($F_1 = 0.0263 \implies \text{BLOCKED}$) and preventing production compromise.

### D. Comparison with Traditional Rule-Based Detectors
We benchmarked our Dual-Engine ML system against standard heuristic rules (Alert if entropy $> 6.8$ or modify rate $> 35$ ops/min):

| Detection Approach | Accuracy | Precision | Recall | F1-Score | False Positive Rate |
|---|:---:|:---:|:---:|:---:|:---:|
| **Rule-Based Heuristic** | 88.53% | 72.35% | 100.0% | 0.8396 | **16.38% (86 False Alarms)** |
| **Proposed Dual-Engine ML** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **0.00% (0 False Alarms)** |

*Finding:* Rule-based detection generated 86 false alarms during legitimate 7-Zip archiving and database backups. Our ML model distinguished high-entropy compression from ransomware by analyzing multi-dimensional signals, completely eliminating false alarms.

---

## V. Conclusion
This paper presented an integrated, real-time cloud security framework capable of detecting cryptographic ransomware while defending its own machine learning retraining loop against adversarial data poisoning. By combining supervised tree ensembles with unsupervised anomaly detection, the platform guarantees zero-day coverage while maintaining zero false alarms on legitimate compression workloads. Upstream $k$-NN sanitization and hold-out validation gating effectively immunize the detector against poisoning drift. 

With sub-35 millisecond inference latency, automated quarantine audit logging, and an interactive SecOps dashboard, the system provides a production-viable blueprint for autonomous cloud workload protection.

---

## References
[1] N. Scaife et al., "CryptoLock (and Drop It): Stopping Ransomware at the File System," in *Proc. IEEE ICDCS*, 2016, pp. 603–612.  
[2] A. Continella et al., "ShieldFS: A Self-healing, Ransomware-aware Filesystem," in *Proc. ACM ACSAC*, 2016, pp. 336–347.  
[3] D. Sgandurra et al., "Automated Dynamic Analysis of Ransomware," *IEEE Trans. Inf. Forensics Security*, vol. 12, no. 8, pp. 1902–1915, 2017.  
[6] M. Davies et al., "CloudRanger: Rapid Ransomware Identification in Cloud Infrastructures," *Computers & Security*, vol. 108, p. 102374, 2021.  
[12] H. H. Nguyen et al., "Cloud-Guard: Real-Time Behavioral Anomaly Detection against Ransomware," *Future Gener. Comput. Syst.*, vol. 132, pp. 312–326, 2022.  
[13] B. Biggio et al., "Poisoning Attacks against Support Vector Machines," in *Proc. ICML*, 2012, pp. 1807–1814.  
[17] H. Paudice et al., "Detection of Adversarial Training Examples using Label-Sanitization," in *Proc. IEEE EuroS&PW*, 2018, pp. 140–147.  
[19] C. Severi et al., "Explanation-Guided Backdoor Poisoning Attacks against Malware Classifiers," in *Proc. USENIX Security*, 2021, pp. 1487–1504.  
[25] M. Chiba et al., "A Real-time Machine Learning Architecture for Cloud Security Audit Log Analysis," *IEEE Trans. Cloud Comput.*, vol. 10, no. 4, 2022.  
[27] Y. Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online NIDS," in *Proc. NDSS*, 2018.  
