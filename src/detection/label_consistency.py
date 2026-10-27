"""
Detection Layer B: Label Consistency Checks
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Uses k-Nearest Neighbors (k-NN) neighborhood topology to detect label-flipping attacks
and corrupted class boundaries where a sample's claimed label contradicts its neighborhood.
"""

from typing import List, Tuple
import numpy as np
from sklearn.neighbors import NearestNeighbors
from src.common.logger import get_logger

logger = get_logger("LabelConsistencyDetector")

class LabelConsistencyDetector:
    def __init__(self, n_neighbors: int = 11):
        self.n_neighbors = n_neighbors
        self.nn_model = None
        self.reference_labels = None
        self.is_fitted = False

    def fit(self, X_ref: np.ndarray, y_ref: np.ndarray) -> "LabelConsistencyDetector":
        self.nn_model = NearestNeighbors(n_neighbors=self.n_neighbors, algorithm="auto", n_jobs=-1)
        self.nn_model.fit(X_ref)
        self.reference_labels = np.asarray(y_ref)
        self.is_fitted = True
        logger.info(f"Label consistency detector fitted on {len(X_ref)} reference samples (k={self.n_neighbors}).")
        return self

    def score_samples(self, X: np.ndarray, y_claimed: np.ndarray) -> np.ndarray:
        """
        Calculates the neighborhood label disagreement score in range [0.0, 1.0].
        Score = 1.0 - (fraction of k-neighbors sharing the sample's claimed label).
        A high score indicates severe neighborhood disagreement (label flipping).
        """
        if not self.is_fitted or self.nn_model is None:
            raise RuntimeError("Label consistency detector must be fitted before scoring.")

        distances, neighbor_indices = self.nn_model.kneighbors(X)
        n_samples = len(X)
        inconsistency_scores = np.zeros(n_samples, dtype=float)

        for i in range(n_samples):
            claimed_label = y_claimed[i]
            neighbor_labs = self.reference_labels[neighbor_indices[i]]
            agreement_ratio = np.mean(neighbor_labs == claimed_label)
            inconsistency_scores[i] = 1.0 - agreement_ratio

        return np.clip(inconsistency_scores, 0.0, 1.0)

if __name__ == "__main__":
    X_ref = np.array([[1.0, 1.0], [1.1, 1.0], [0.9, 1.2], [5.0, 5.0], [5.1, 5.2], [4.9, 5.1]])
    y_ref = np.array([0, 0, 0, 1, 1, 1])
    det = LabelConsistencyDetector(n_neighbors=3)
    det.fit(X_ref, y_ref)
    
    # Query a point near cluster 0 with claimed label 1 (label flipped!)
    X_test = np.array([[1.0, 1.0]])
    y_test = np.array([1]) # Claimed 1, but surrounded by 0s
    score = det.score_samples(X_test, y_test)
    print("Inconsistency score for flipped label:", score[0]) # Should be 1.0
