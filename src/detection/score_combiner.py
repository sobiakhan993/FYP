"""
Multi-Layer Risk Score Combiner & Decision Policy
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Combines signals from:
- Layer A (Statistical Anomaly)
- Layer B (Label Consistency)
- Layer C (Model-Based Disparity)
Produces an explainable categorical decision: ACCEPTED, QUARANTINED, or REVIEW_REQUIRED.
"""

from typing import Dict, Any, List, Tuple
import numpy as np
from src.common.config import get_detectors_config
from src.common.types import DecisionCategory

class RiskScoreCombiner:
    def __init__(self, config: Dict[str, Any] = None):
        cfg = config or get_detectors_config()
        self.det_cfg = cfg.get("detectors", {})
        self.comb_cfg = cfg.get("combiner", {})

        # Weights
        self.w_a = self.det_cfg.get("layer_a_statistical", {}).get("weight", 0.35)
        self.w_b = self.det_cfg.get("layer_b_label_consistency", {}).get("weight", 0.40)
        self.w_c = self.det_cfg.get("layer_c_model_based", {}).get("weight", 0.25)
        
        # Normalize weights to sum to 1.0
        total_w = self.w_a + self.w_b + self.w_c
        if total_w > 0:
            self.w_a /= total_w
            self.w_b /= total_w
            self.w_c /= total_w

        # Thresholds
        self.quarantine_threshold = self.comb_cfg.get("quarantine_threshold", 0.50)
        self.review_threshold = self.comb_cfg.get("suspicious_review_threshold", 0.35)
        self.policy = self.comb_cfg.get("decision_policy", "weighted_score")

    def combine(
        self,
        scores_a: np.ndarray,
        scores_b: np.ndarray,
        scores_c: np.ndarray
    ) -> List[Dict[str, Any]]:
        n_samples = len(scores_a)
        results = []

        for i in range(n_samples):
            sa = float(scores_a[i])
            sb = float(scores_b[i])
            sc = float(scores_c[i])

            if self.policy == "weighted_score":
                combined_score = (self.w_a * sa) + (self.w_b * sb) + (self.w_c * sc)
            elif self.policy == "majority_vote":
                votes = sum([sa >= 0.55, sb >= 0.50, sc >= 0.65])
                combined_score = votes / 3.0
            elif self.policy == "any_trigger":
                combined_score = max(sa, sb, sc)
            else:
                combined_score = (self.w_a * sa) + (self.w_b * sb) + (self.w_c * sc)

            reasons = []
            if sa >= 0.55:
                reasons.append(f"Statistical Anomaly (Layer A: {sa:.2f})")
            if sb >= 0.50:
                reasons.append(f"Label Inconsistency (Layer B: {sb:.2f})")
            if sc >= 0.65:
                reasons.append(f"Model Loss Disparity (Layer C: {sc:.2f})")

            if combined_score >= self.quarantine_threshold:
                category = DecisionCategory.QUARANTINED
                reason_str = " | ".join(reasons) if reasons else f"Composite risk ({combined_score:.2f}) exceeded threshold"
            elif combined_score >= self.review_threshold:
                category = DecisionCategory.REVIEW_REQUIRED
                reason_str = "Elevated risk requiring operator triage: " + (", ".join(reasons) if reasons else "moderate anomaly")
            else:
                category = DecisionCategory.ACCEPTED
                reason_str = "Passed multi-layer sanitization checks"

            results.append({
                "combined_score": round(combined_score, 4),
                "decision": category.value,
                "layer_scores": {
                    "layer_a_statistical": round(sa, 4),
                    "layer_b_label_consistency": round(sb, 4),
                    "layer_c_model_based": round(sc, 4)
                },
                "reason": reason_str
            })

        return results
