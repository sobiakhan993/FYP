"""
Unit Tests: Multi-Layer Detection & Score Combiner
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import pytest
import numpy as np
from src.detection.statistical import StatisticalAnomalyDetector
from src.detection.label_consistency import LabelConsistencyDetector
from src.detection.model_based import ModelBasedDetector
from src.detection.score_combiner import RiskScoreCombiner
from src.common.types import DecisionCategory

def test_statistical_detector_flags_outliers():
    rng = np.random.default_rng(42)
    X_train = rng.normal(0, 1, size=(200, 3))
    det = StatisticalAnomalyDetector(contamination=0.10)
    det.fit(X_train)

    X_inlier = np.array([[0.0, 0.1, -0.1]])
    X_outlier = np.array([[20.0, 25.0, 30.0]])

    score_inlier = det.score_samples(X_inlier)[0]
    score_outlier = det.score_samples(X_outlier)[0]

    assert score_outlier > score_inlier
    assert score_outlier > 0.50

def test_label_consistency_flags_flipped_labels():
    # Dense cluster of label 0
    X_ref = np.array([[1.0, 1.0], [1.1, 1.0], [0.9, 1.2], [1.0, 0.9]])
    y_ref = np.array([0, 0, 0, 0])
    
    det = LabelConsistencyDetector(n_neighbors=3)
    det.fit(X_ref, y_ref)

    # Claim label 1 inside cluster 0
    score = det.score_samples(np.array([[1.0, 1.0]]), np.array([1]))[0]
    assert score == 1.0 # 100% inconsistency

def test_risk_score_combiner_decisions():
    combiner = RiskScoreCombiner()
    # High risk point
    s_a = np.array([0.80])
    s_b = np.array([0.90])
    s_c = np.array([0.75])

    res = combiner.combine(s_a, s_b, s_c)
    assert res[0]["decision"] == DecisionCategory.QUARANTINED.value
    assert res[0]["combined_score"] > 0.50

    # Clean point
    s_a_clean = np.array([0.10])
    s_b_clean = np.array([0.05])
    s_c_clean = np.array([0.02])
    res_clean = combiner.combine(s_a_clean, s_b_clean, s_c_clean)
    assert res_clean[0]["decision"] == DecisionCategory.ACCEPTED.value
