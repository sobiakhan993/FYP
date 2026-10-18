# Baseline Model Evaluation & Poisoning Vulnerability Report

### 1. Clean Data Benchmark Results

| Model                           | Dataset           | Val Acc   | Val F1   |   Test Acc |   Test Precision |   Test Recall |   Test F1 |   Test FPR |   Test AUC | CM (TN/FP/FN/TP)   |
|:--------------------------------|:------------------|:----------|:---------|-----------:|-----------------:|--------------:|----------:|-----------:|-----------:|:-------------------|
| Logistic Regression             | Clean Data        | 1.0       | 1.0      |     1      |           1      |             1 |    1      |     0      |          1 | 525/0/0/225        |
| Random Forest                   | Clean Data        | 1.0       | 1.0      |     1      |           1      |             1 |    1      |     0      |          1 | 525/0/0/225        |
| Gradient Boosting               | Clean Data        | 1.0       | 1.0      |     1      |           1      |             1 |    1      |     0      |          1 | 525/0/0/225        |
| Isolation Forest (Unsupervised) | Clean Normal-Only | N/A       | N/A      |     0.9267 |           0.8036 |             1 |    0.8911 |     0.1048 |          1 | 470/55/0/225       |

### 2. Impact of 10% Training Data Poisoning (Label-Flipping Attack)

| Model               | Dataset                   |   Test Acc |   Test Precision |   Test Recall |   Test F1 |   Test FPR |   Test AUC | CM (TN/FP/FN/TP)   |
|:--------------------|:--------------------------|-----------:|-----------------:|--------------:|----------:|-----------:|-----------:|:-------------------|
| Logistic Regression | 10% Poisoned (Label-Flip) |     0.9853 |                1 |        0.9511 |    0.9749 |          0 |          1 | 525/0/11/214       |
| Random Forest       | 10% Poisoned (Label-Flip) |     0.9853 |                1 |        0.9511 |    0.9749 |          0 |          1 | 525/0/11/214       |
| Gradient Boosting   | 10% Poisoned (Label-Flip) |     0.9707 |                1 |        0.9022 |    0.9486 |          0 |          1 | 525/0/22/203       |

### 3. Key Observations
- **Random Forest & Gradient Boosting** achieve exceptional detection performance (>98% F1-score, FPR < 2%) under clean conditions.
- **Poisoning Vulnerability Confirmed:** When exposed to 10% label flipping, models experience immediate recall degradation and false negative spikes, allowing real attacks to slip past.
- **Unsupervised Isolation Forest** achieves high detection recall without labeled data, validating its utility as a second layer for zero-day behaviors.
