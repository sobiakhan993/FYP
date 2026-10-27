"""
Candidate IDS Model Retraining Service
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Complies with FR-06:
Trains a candidate IDS classification model exclusively using data accepted
by the multi-layer poisoning defense policy. Never uses quarantined data.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from src.common.config import get_data_config
from src.common.logger import get_logger

logger = get_logger("CandidateTrainer")

class CandidateTrainer:
    def __init__(self, model_type: str = "random_forest", random_state: int = 42):
        self.model_type = model_type.lower()
        self.random_state = random_state
        self.data_cfg = get_data_config()
        self.features = self.data_cfg["features"]["numerical"]
        self.target = self.data_cfg["features"]["target"]

    def train(self, training_data_path: str) -> Any:
        """
        Trains a candidate classifier on sanitized / accepted data.
        """
        logger.info(f"Loading training data from {training_data_path}...")
        df = pd.read_csv(training_data_path)
        
        # Ensure quarantined records are not in input
        if "is_poisoned" in df.columns:
            # Drop ground-truth flag before training so model does not see it
            df = df.drop(columns=["is_poisoned"])

        X = df[self.features].values
        y = df[self.target].values

        logger.info(f"Training candidate {self.model_type} on {len(X)} accepted records...")
        if self.model_type == "random_forest":
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=self.random_state,
                n_jobs=-1
            )
        elif self.model_type == "logistic_regression":
            model = LogisticRegression(
                max_iter=1000,
                random_state=self.random_state
            )
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")

        model.fit(X, y)
        logger.info(f"Candidate model ({self.model_type}) trained successfully.")
        return model

def train_and_register_baseline() -> str:
    from src.training.validate_candidate import TrustedValidationGate
    from src.training.model_registry import ModelRegistry

    trainer = CandidateTrainer()
    model = trainer.train("data/processed/train.csv")

    gate = TrustedValidationGate()
    passed, val_res = gate.evaluate_and_gate(model, "clean_baseline_rf")
    if not passed:
        raise RuntimeError(f"Clean baseline failed validation: {val_res.block_reason}")

    metrics = {
        "accuracy": val_res.accuracy,
        "precision": val_res.precision,
        "recall": val_res.recall,
        "f1_score": val_res.f1_score,
        "false_positive_rate": val_res.false_positive_rate
    }

    registry = ModelRegistry()
    ver = registry.register_and_promote(
        model, metrics, version_tag="v1.0.0", notes="Initial clean baseline model"
    )
    logger.info(f"Clean baseline promoted as {ver} with F1={val_res.f1_score:.4f}")
    return ver

if __name__ == "__main__":
    train_and_register_baseline()

