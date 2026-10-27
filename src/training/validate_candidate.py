"""
Trusted Validation Gate
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Complies with FR-07 & FR-08:
Evaluates candidate models against the isolated, clean holdout dataset.
Enforces performance regression limits: If a candidate model degrades
below the currently approved baseline (e.g. F1-score drop > 3%), the gate
BLOCKS promotion, preserving system stability and model security.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from src.common.config import get_data_config
from src.common.logger import get_logger
from src.common.types import ModelValidationResult

logger = get_logger("TrustedValidationGate")

class TrustedValidationGate:
    def __init__(
        self,
        trusted_holdout_path: Optional[str] = None,
        regression_tolerance: float = 0.03, # Max allowable drop in F1-score: 3%
        min_f1_threshold: float = 0.85
    ):
        cfg = get_data_config()
        self.holdout_path = Path(
            trusted_holdout_path or cfg["dataset"].get("trusted_holdout_path", "data/processed/trusted_validation.csv")
        )
        self.regression_tolerance = regression_tolerance
        self.min_f1_threshold = min_f1_threshold
        self.features = cfg["features"]["numerical"]
        self.target = cfg["features"]["target"]

        logger.info(f"Loading isolated trusted validation set: {self.holdout_path}")
        self.df_holdout = pd.read_csv(self.holdout_path)
        self.X_holdout = self.df_holdout[self.features].values
        self.y_holdout = self.df_holdout[self.target].values
        logger.info(f"Trusted holdout ready with {len(self.df_holdout)} clean verification records.")

    def evaluate_model(self, model: Any) -> Dict[str, float]:
        preds = model.predict(self.X_holdout)
        acc = float(accuracy_score(self.y_holdout, preds))
        prec = float(precision_score(self.y_holdout, preds, zero_division=0))
        rec = float(recall_score(self.y_holdout, preds, zero_division=0))
        f1 = float(f1_score(self.y_holdout, preds, zero_division=0))

        cm = confusion_matrix(self.y_holdout, preds)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4)
        }

    def evaluate_and_gate(
        self,
        candidate_model: Any,
        candidate_id: str,
        active_baseline_metrics: Optional[Dict[str, float]] = None
    ) -> Tuple[bool, ModelValidationResult]:
        metrics = self.evaluate_model(candidate_model)
        cand_f1 = metrics["f1_score"]
        now_str = datetime.now(timezone.utc).isoformat()

        passed = True
        block_reason = None

        # Check 1: Minimum baseline performance
        if cand_f1 < self.min_f1_threshold:
            passed = False
            block_reason = f"Candidate F1-score ({cand_f1:.4f}) fell below minimum acceptable threshold ({self.min_f1_threshold:.4f})"

        # Check 2: Regression comparison against currently approved active model
        if passed and active_baseline_metrics:
            active_f1 = active_baseline_metrics.get("f1_score", 0.0)
            f1_drop = active_f1 - cand_f1
            if f1_drop > self.regression_tolerance:
                passed = False
                block_reason = (
                    f"Performance regression detected: F1 drop of {f1_drop:.4f} "
                    f"exceeds tolerance of {self.regression_tolerance:.4f} "
                    f"(Active={active_f1:.4f}, Candidate={cand_f1:.4f})"
                )

        if passed:
            logger.info(f"Validation Gate PASSED for {candidate_id}: F1={cand_f1:.4f}")
        else:
            logger.warning(f"Validation Gate BLOCKED promotion for {candidate_id}: {block_reason}")

        result = ModelValidationResult(
            model_id=candidate_id,
            version="candidate",
            dataset_version="trusted_holdout_v1",
            evaluated_at=now_str,
            accuracy=metrics["accuracy"],
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1_score=metrics["f1_score"],
            false_positive_rate=metrics["false_positive_rate"],
            passed=passed,
            block_reason=block_reason
        )

        return passed, result

if __name__ == "__main__":
    gate = TrustedValidationGate()
    from sklearn.dummy import DummyClassifier
    bad_model = DummyClassifier(strategy="constant", constant=0)
    bad_model.fit(gate.X_holdout, gate.y_holdout)
    passed, res = gate.evaluate_and_gate(bad_model, "dummy_bad_model")
    print("Gating outcome:", passed, res.block_reason)
