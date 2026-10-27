"""
Detection Layer C: Model-Based Checks
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Evaluates per-sample prediction loss margin and confidence disparity against
the currently approved production IDS model.
"""

from typing import Any
import numpy as np
from src.common.logger import get_logger

logger = get_logger("ModelBasedDetector")

class ModelBasedDetector:
    def __init__(self, active_ids_model: Any = None):
        self.active_ids_model = active_ids_model

    def set_active_model(self, model: Any) -> None:
        self.active_ids_model = model

    def score_samples(self, X: np.ndarray, y_claimed: np.ndarray) -> np.ndarray:
        """
        Calculates confidence disparity risk score in range [0.0, 1.0].
        Score = 1.0 - P(y_claimed | X).
        If the active model is 99% confident that the sample is Malicious (1),
        but the claimed label is Benign (0), the score is 0.99 (flagged).
        """
        if self.active_ids_model is None:
            # If no model is loaded yet, return neutral risk 0.0
            return np.zeros(len(X), dtype=float)

        n_samples = len(X)
        disparity_scores = np.zeros(n_samples, dtype=float)

        if hasattr(self.active_ids_model, "predict_proba"):
            probs = self.active_ids_model.predict_proba(X)
            classes = list(self.active_ids_model.classes_)
            
            for i in range(n_samples):
                claimed = y_claimed[i]
                if claimed in classes:
                    class_idx = classes.index(claimed)
                    claimed_prob = probs[i, class_idx]
                else:
                    claimed_prob = 0.0
                disparity_scores[i] = 1.0 - claimed_prob
        elif hasattr(self.active_ids_model, "decision_function"):
            raw = self.active_ids_model.decision_function(X)
            prob_1 = 1.0 / (1.0 + np.exp(-raw))
            for i in range(n_samples):
                claimed = y_claimed[i]
                claimed_prob = prob_1[i] if claimed == 1 else (1.0 - prob_1[i])
                disparity_scores[i] = 1.0 - claimed_prob
        else:
            preds = self.active_ids_model.predict(X)
            disparity_scores = (preds != y_claimed).astype(float)

        return np.clip(disparity_scores, 0.0, 1.0)
