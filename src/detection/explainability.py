"""
Explainability & Forensic Feature Attribution Engine
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
Industry 5.0 Trustworthy & Explainable AI Component

Provides:
- Statistical z-score deviations relative to clean baseline distributions.
- Feature contribution ranking for quarantined and anomalous network records.
- Topological neighborhood context for stealth label-flipping diagnosis.
"""

from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from src.common.config import get_data_config
from src.common.logger import get_logger

logger = get_logger("ExplainabilityEngine")

class FlowExplainabilityEngine:
    def __init__(self, reference_df: pd.DataFrame = None):
        cfg = get_data_config()
        self.features = cfg["features"]["numerical"]
        self.target = cfg["features"]["target"]

        if reference_df is None:
            reference_df = pd.read_csv("data/processed/val.csv")

        self.ref_means = reference_df[self.features].mean().to_dict()
        self.ref_stds = reference_df[self.features].std().replace(0, 1.0).to_dict()

        # Class-conditional reference profiles
        self.benign_means = reference_df[reference_df[self.target] == 0][self.features].mean().to_dict()
        self.attack_means = reference_df[reference_df[self.target] == 1][self.features].mean().to_dict()
        logger.info(f"Explainability engine initialized across {len(self.features)} flow features.")

    def explain_record(
        self,
        features: Dict[str, float],
        claimed_label: int,
        layer_scores: Dict[str, float],
        combined_score: float
    ) -> Dict[str, Any]:
        """
        Generates structured forensic attribution explaining WHY a sample was quarantined.
        """
        deviations = {}
        target_cluster = self.benign_means if claimed_label == 0 else self.attack_means
        opposite_cluster = self.attack_means if claimed_label == 0 else self.benign_means

        for feat in self.features:
            val = float(features.get(feat, 0.0))
            mean_val = self.ref_means.get(feat, 0.0)
            std_val = self.ref_stds.get(feat, 1.0)
            z_score = (val - mean_val) / std_val

            # Distance to claimed class vs distance to opposite class
            claimed_dist = abs(val - target_cluster.get(feat, 0.0))
            opposite_dist = abs(val - opposite_cluster.get(feat, 0.0))

            deviations[feat] = {
                "value": round(val, 4),
                "z_score": round(z_score, 2),
                "closer_to_opposite": bool(opposite_dist < claimed_dist),
                "deviation_impact": round(abs(z_score), 2)
            }

        # Sort features by highest deviation impact
        top_deviations = sorted(
            deviations.items(), key=lambda item: item[1]["deviation_impact"], reverse=True
        )[:4]

        top_contributors = []
        for feat, info in top_deviations:
            dir_str = "significantly higher than normal" if info["z_score"] > 0 else "significantly lower than normal"
            top_contributors.append({
                "feature": feat,
                "value": info["value"],
                "z_score": info["z_score"],
                "explanation": f"{feat} is {dir_str} (Z={info['z_score']:+.2f})"
            })

        # Forensic threat characterization
        is_label_flip = layer_scores.get("layer_b_label_consistency", 0.0) >= 0.50
        is_stat_outlier = layer_scores.get("layer_a_statistical", 0.0) >= 0.55
        is_loss_disparity = layer_scores.get("layer_c_model_based", 0.0) >= 0.65

        if is_label_flip and is_loss_disparity:
            diagnosis = "Stealth Label-Flipping Evasion: Network flow vector exhibits attack patterns but was deceptively labeled as Benign."
            threat_type = "LABEL_FLIPPING"
        elif is_stat_outlier and not is_label_flip:
            diagnosis = "Distributional Boundary Anomaly: Crafted vector perturbed away from normal manifold."
            threat_type = "SAMPLE_INJECTION"
        else:
            diagnosis = "Multi-Layer Composite Risk Violation: Combined risk score exceeded safe retraining threshold."
            threat_type = "COMPOSITE_RISK"

        return {
            "combined_risk_score": combined_score,
            "threat_diagnosis": diagnosis,
            "threat_type": threat_type,
            "top_attributions": top_contributors,
            "layer_breakdown": layer_scores
        }

if __name__ == "__main__":
    exp = FlowExplainabilityEngine()
    dummy_feat = {f: 0.0 for f in exp.features}
    dummy_feat["flow_bytes_per_sec"] = 4.5
    dummy_feat["syn_flag_count"] = 3.2
    res = exp.explain_record(
        dummy_feat,
        claimed_label=0,
        layer_scores={"layer_a_statistical": 0.85, "layer_b_label_consistency": 0.95, "layer_c_model_based": 0.90},
        combined_score=0.91
    )
    print("Forensic Explanation:\n", res)
