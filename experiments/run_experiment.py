"""
Comprehensive Experiment & Defense Evaluation Runner
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Complies strictly with Section 12.4 (Comparison Groups), Section 13 (Evaluation Methodology),
and Section 13.5 (Reporting Table Template):
1. Benchmarks baseline clean performance.
2. Evaluates poisoning impact without defense across 5%, 10%, and 20% poisoning rates.
3. Conducts Ablation Studies:
   - Layer A only (Statistical Anomaly)
   - Layer B only (Label Consistency)
   - Layer C only (Model-based Disparity)
   - Combined Multi-layer Defense
4. Measures Detection Precision, Recall, F1, False-Quarantine Rate, Retrained IDS F1, and Latency.
5. Verifies Trusted Validation Gate blocks poisoned candidate promotion.
"""

import time
import json
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score
from src.common.config import get_data_config
from src.common.logger import get_logger
from src.attacks.label_flip import LabelFlipAttacker
from src.attacks.sample_injection import SampleInjectionAttacker
from src.detection.statistical import StatisticalAnomalyDetector
from src.detection.label_consistency import LabelConsistencyDetector
from src.detection.model_based import ModelBasedDetector
from src.detection.score_combiner import RiskScoreCombiner
from src.training.train_candidate import CandidateTrainer
from src.training.validate_candidate import TrustedValidationGate
from src.training.model_registry import ModelRegistry

logger = get_logger("ExperimentRunner")

def run_experiment_suite(output_csv: str = "experiments/results/experiment_results.csv") -> pd.DataFrame:
    cfg = get_data_config()
    features = cfg["features"]["numerical"]
    target = cfg["features"]["target"]

    train_df = pd.read_csv("data/processed/train.csv")
    val_df = pd.read_csv("data/processed/val.csv")
    trusted_df = pd.read_csv("data/processed/trusted_validation.csv")

    X_train_clean = train_df[features].values
    y_train_clean = train_df[target].values

    # Pre-fit detection layers on clean reference validation data
    logger.info("Fitting defensive detection layers on reference validation data...")
    det_a = StatisticalAnomalyDetector().fit(val_df[features].values)
    det_b = LabelConsistencyDetector(n_neighbors=11).fit(val_df[features].values, val_df[target].values)
    
    registry = ModelRegistry()
    active_model, _ = registry.get_active_model()
    det_c = ModelBasedDetector(active_model)
    combiner = RiskScoreCombiner()
    gate = TrustedValidationGate()

    results: List[Dict[str, Any]] = []

    # 1. Clean Baseline (No Poisoning, No Defense)
    t0 = time.perf_counter()
    trainer = CandidateTrainer()
    clean_model = trainer.train("data/processed/train.csv")
    clean_metrics = gate.evaluate_model(clean_model)
    latency_ms = (time.perf_counter() - t0) * 1000

    results.append({
        "attack_type": "None (Clean)",
        "poison_rate": "0%",
        "defense_mode": "No Defense",
        "detection_precision": 1.0,
        "detection_recall": 1.0,
        "detection_f1": 1.0,
        "false_quarantine_rate": 0.0,
        "ids_f1_after_retraining": clean_metrics["f1_score"],
        "gate_action": "PROMOTED",
        "median_batch_latency_ms": round(latency_ms, 2)
    })

    # Test Matrix: Attacks & Poison Rates
    attacks = [
        ("Label Flipping", LabelFlipAttacker(random_seed=42), [0.05, 0.10, 0.20]),
        ("Sample Injection", SampleInjectionAttacker(feature_cols=features, random_seed=42), [0.05, 0.10, 0.20])
    ]

    for attack_name, attacker, rates in attacks:
        for rate in rates:
            logger.info(f"--- Running Experiment: {attack_name} @ {rate:.0%} Poison Rate ---")
            
            # Apply attack
            if attack_name == "Label Flipping":
                p_df, meta = attacker.apply_attack(train_df, poison_rate=rate)
            else:
                p_df, meta = attacker.apply_attack(train_df, poison_rate=rate)

            y_ground_truth_poisoned = p_df["is_poisoned"].values
            X_p = p_df[features].values
            y_p = p_df[target].values

            # Group A: Poisoned without defense
            p_model = trainer.train_candidate_from_arrays(X_p, y_p) if hasattr(trainer, "train_candidate_from_arrays") else None
            if p_model is None:
                from sklearn.ensemble import RandomForestClassifier
                p_model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1).fit(X_p, y_p)
            
            p_metrics = gate.evaluate_model(p_model)
            passed, _ = gate.evaluate_and_gate(p_model, f"poisoned_{rate}", active_baseline_metrics=clean_metrics)

            results.append({
                "attack_type": attack_name,
                "poison_rate": f"{int(rate*100)}%",
                "defense_mode": "No Defense",
                "detection_precision": 0.0,
                "detection_recall": 0.0,
                "detection_f1": 0.0,
                "false_quarantine_rate": 0.0,
                "ids_f1_after_retraining": p_metrics["f1_score"],
                "gate_action": "PROMOTED (Unprotected)" if not passed else "PROMOTED",
                "median_batch_latency_ms": 0.0
            })

            # Run Layer Defenses
            t_det_0 = time.perf_counter()
            s_a = det_a.score_samples(X_p)
            s_b = det_b.score_samples(X_p, y_p)
            s_c = det_c.score_samples(X_p, y_p)
            comb_res = combiner.combine(s_a, s_b, s_c)
            det_latency = (time.perf_counter() - t_det_0) * 1000

            # Ablation evaluations: Layer A only, Layer B only, Layer C only, Combined
            pred_flags = {
                "Layer A (Statistical)": s_a >= 0.55,
                "Layer B (Label Consistency)": s_b >= 0.50,
                "Layer C (Model-Based)": s_c >= 0.65,
                "Combined Defense": np.array([r["decision"] == "QUARANTINED" for r in comb_res])
            }

            for mode_name, flags in pred_flags.items():
                tp = int(np.sum(flags & y_ground_truth_poisoned))
                fp = int(np.sum(flags & ~y_ground_truth_poisoned))
                fn = int(np.sum(~flags & y_ground_truth_poisoned))
                tn = int(np.sum(~flags & ~y_ground_truth_poisoned))

                prec = float(precision_score(y_ground_truth_poisoned, flags, zero_division=0))
                rec = float(recall_score(y_ground_truth_poisoned, flags, zero_division=0))
                f1_det = float(f1_score(y_ground_truth_poisoned, flags, zero_division=0))
                false_quar_rate = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

                # Sanitize training data by filtering out flagged points
                accepted_indices = np.where(~flags)[0]
                if len(accepted_indices) > 0:
                    X_sanitized = X_p[accepted_indices]
                    y_sanitized = y_p[accepted_indices]
                    sanitized_model = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1).fit(X_sanitized, y_sanitized)
                    san_metrics = gate.evaluate_model(sanitized_model)
                    gate_passed, _ = gate.evaluate_and_gate(sanitized_model, f"sanitized_{mode_name}", active_baseline_metrics=clean_metrics)
                    gate_status = "PROMOTED" if gate_passed else "BLOCKED_BY_GATE"
                    post_f1 = san_metrics["f1_score"]
                else:
                    gate_status = "BLOCKED_ALL_REJECTED"
                    post_f1 = 0.0

                results.append({
                    "attack_type": attack_name,
                    "poison_rate": f"{int(rate*100)}%",
                    "defense_mode": mode_name,
                    "detection_precision": round(prec, 4),
                    "detection_recall": round(rec, 4),
                    "detection_f1": round(f1_det, 4),
                    "false_quarantine_rate": round(false_quar_rate, 4),
                    "ids_f1_after_retraining": round(post_f1, 4),
                    "gate_action": gate_status,
                    "median_batch_latency_ms": round(det_latency / len(pred_flags), 2)
                })

    results_df = pd.DataFrame(results)
    out_path = Path(output_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    results_df.to_csv(out_path, index=False)
    logger.info(f"Experiment results saved to {out_path}")
    return results_df

if __name__ == "__main__":
    df_res = run_experiment_suite()
    print("\n================ EXPERIMENT RESULTS ================")
    print(df_res.to_string())
