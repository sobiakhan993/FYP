"""
Detection Layer A: Statistical Anomaly Checks
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Uses Isolation Forest and Local Outlier Factor (LOF) to flag feature space
distribution outliers and anomalous vector distances.
"""

from typing import Dict, Any, List
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from src.common.logger import get_logger

logger = get_logger("StatisticalDetector")

class StatisticalAnomalyDetector:
    def __init__(self, algorithm: str = "isolation_forest", contamination: float = 0.08, random_state: int = 42):
        self.algorithm = algorithm.lower()
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.is_fitted = False

    def fit(self, X: np.ndarray) -> "StatisticalAnomalyDetector":
        if self.algorithm == "isolation_forest":
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1
            )
            self.model.fit(X)
        elif self.algorithm == "local_outlier_factor":
            self.model = LocalOutlierFactor(
                n_neighbors=20,
                contamination=self.contamination,
                novelty=True, # Allows score_samples on new incoming stream records
                n_jobs=-1
            )
            self.model.fit(X)
        else:
            raise ValueError(f"Unsupported statistical detector algorithm: {self.algorithm}")

        self.is_fitted = True
        logger.info(f"Statistical detector ({self.algorithm}) fitted on {len(X)} reference samples.")
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Returns normalized anomaly risk scores in range [0.0, 1.0].
        Higher score = more anomalous.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError("Statistical anomaly detector must be fitted before scoring.")

        if self.algorithm == "isolation_forest":
            # decision_function yields positive for inliers, negative for outliers
            raw_scores = self.model.decision_function(X)
            # Map into [0.0, 1.0] where 1.0 is most anomalous
            # Typ raw_scores range from ~ -0.5 to +0.3
            normalized = 1.0 / (1.0 + np.exp(raw_scores * 6.0))
            return np.clip(normalized, 0.0, 1.0)
        else:
            raw_scores = self.model.decision_function(X)
            normalized = 1.0 / (1.0 + np.exp(raw_scores * 4.0))
            return np.clip(normalized, 0.0, 1.0)

if __name__ == "__main__":
    X_ref = np.random.normal(0, 1, size=(500, 5))
    det = StatisticalAnomalyDetector()
    det.fit(X_ref)
    X_test = np.array([[0, 0, 0, 0, 0], [10, 10, 10, 10, 10]])
    scores = det.score_samples(X_test)
    print("Scores (inlier vs outlier):", scores)
