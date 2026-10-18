# Benchmark Comparison: Machine Learning vs Rule-Based Detection

| Detection Approach                                            | Accuracy   | Precision   | Recall   |   F1-Score | False Positive Rate   |   False Positives (Benign Flagged) |
|:--------------------------------------------------------------|:-----------|:------------|:---------|-----------:|:----------------------|-----------------------------------:|
| Simple Rule-Based Heuristics (Entropy > 6.8 or Mod Rate > 35) | 88.53%     | 72.35%      | 100.0%   |     0.8396 | 16.38%                |                                 86 |
| Proposed Dual-Engine Machine Learning (RF + Isolation Forest) | 100.0%     | 100.0%      | 100.0%   |     1      | 0.0%                  |                                  0 |

### Analytical Conclusion:
- The rule-based detector generates an unacceptable false positive rate of **16.38%**, incorrectly alerting on **86** benign cloud operations (such as routine 7-Zip compression and database backups).
- In sharp contrast, our **Dual-Engine Machine Learning system** achieves an F1-score of **1.0** with a False Positive Rate of only **0.0%**, drastically reducing alert fatigue for Security Operations Center (SOC) teams.
