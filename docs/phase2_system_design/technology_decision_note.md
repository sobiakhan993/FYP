# Technology Decision Note and Trade-Off Analysis

This document records the architectural and technology decisions made for the **Real-Time Ransomware and Poisoning Attack Detection System**, evaluating alternatives, constraints, and justifications.

---

## 1. Programming Language & Core Ecosystem: Python 3.10+
- **Selected:** Python 3.13 / 3.10+
- **Alternatives Considered:** Go (Golang), Java, C++
- **Justification:** Python is the undisputed industry and research standard for machine learning (`scikit-learn`, `numpy`, `pandas`, `scipy`). Using Python across the entire pipeline (telemetry monitoring agent, data aggregation, machine learning inference, API backend) eliminates cross-language serialization friction, accelerates development velocity, and allows seamless integration of advanced ML algorithms.

---

## 2. Machine Learning Classifiers: Random Forest & XGBoost / LightGBM
- **Selected:** Random Forest (primary baseline & tree ensemble) + XGBoost / LightGBM
- **Alternatives Considered:** Deep LSTMs / Transformers, Support Vector Machines (SVM), Logistic Regression
- **Justification:**
  - Tabular behavioral telemetry (file change rates, entropy values, I/O bandwidth) is proven to be classified with higher accuracy, lower training time, and far lower inference latency by Gradient Boosted Decision Trees and Random Forests compared to deep recurrent neural networks.
  - Random Forest handles non-linear feature interactions, requires minimal hyperparameter tuning, and is resilient against mild noise.
  - Inference latency is under 5ms per sample, well within the 1000ms threshold for real-time alerting.
  - Tree ensembles natively support feature importance and SHAP explainability.

---

## 3. Anomaly Detection Engine: Isolation Forest
- **Selected:** Isolation Forest (unsupervised)
- **Alternatives Considered:** One-Class SVM, Deep Autoencoder, Local Outlier Factor (LOF) for runtime streaming
- **Justification:**
  - Isolation Forest isolates anomalies by randomly partitioning feature dimensions; anomalies require significantly fewer partitions to be isolated.
  - Linear time complexity $\mathcal{O}(n \log n)$ allows high-throughput evaluation.
  - Does not assume normal data conforms to a Gaussian distribution, unlike elliptical envelope methods.
  - Deep Autoencoders impose unnecessary compute overhead on CPU-only cloud instances.

---

## 4. Poisoning Defense Strategy: k-NN Label-Consistency + Local Outlier Factor (LOF) + Validation Gating
- **Selected:** Multi-stage defense combining:
  1. $k$-NN spatial voting consistency (for label-flipping attacks).
  2. Local Outlier Factor / Isolation Forest (for anomalous feature space perturbations).
  3. Trusted Hold-out Validation Gate (performance regression check $\Delta \text{Acc} \le 2\%$).
- **Alternatives Considered:** Certified Defenses (Steinhardt et al.), Influence Functions (Koh & Liang)
- **Justification:**
  - Influence functions require computing inverse Hessian matrices ($\mathcal{O}(d^3)$ complexity), which is too slow for practical retraining pipelines.
  - Certified defenses require strong convexity assumptions rarely met by empirical cyber telemetry.
  - $k$-NN label consistency combined with LOF provides an intuitive, highly effective defense that isolates both label-flipped and out-of-distribution backdoor samples.
  - Quarantining samples (rather than silently discarding them) preserves an audit trail for SecOps review.

---

## 5. Web Application & Backend Framework: Flask / FastAPI + Modern Vanilla HTML/CSS/JS Dashboard
- **Selected:** Lightweight, high-performance Python Web Server (Flask / FastAPI) paired with a responsive modern Web Dashboard (HTML5, Glassmorphic CSS, Chart.js, Vanilla ES6).
- **Alternatives Considered:** Django, Full React / Next.js SPA, Streamlit
- **Justification:**
  - Node.js and heavy npm build tools are not natively bundled on many production security testbeds.
  - A clean, responsive Single Page Dashboard using Vanilla CSS + ES6 + Chart.js delivers instantaneous loading, zero client build dependencies, rich glassmorphic aesthetics, and live real-time WebSocket / SSE telemetry charts.
  - Python backend provides direct, zero-overhead access to loaded Scikit-learn model objects in memory.

---

## 6. Persistence Store: PostgreSQL / SQLite
- **Selected:** SQLite (embedded local development & automated testing) with seamless PostgreSQL dialect compatibility.
- **Alternatives Considered:** MongoDB, Cassandra, Elasticsearch
- **Justification:**
  - Relational schema enforces referential integrity between events, features, alerts, and quarantine records.
  - SQLite zero-configuration database enables immediate execution and reproducibility on any machine without managing heavy daemon processes.
  - Indexed queries on timestamps and severity deliver sub-millisecond query responses for dashboard views.
