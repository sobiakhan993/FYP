"""
Unit Tests: Candidate Trainer, Trusted Validation Gate & Model Registry Rollback
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import shutil
import pytest
from pathlib import Path
from sklearn.dummy import DummyClassifier
from src.training.train_candidate import CandidateTrainer
from src.training.validate_candidate import TrustedValidationGate
from src.training.model_registry import ModelRegistry

TEST_REGISTRY_DIR = "models/test_registry"

@pytest.fixture(autouse=True)
def cleanup():
    if Path(TEST_REGISTRY_DIR).exists():
        shutil.rmtree(TEST_REGISTRY_DIR, ignore_errors=True)
    yield
    if Path(TEST_REGISTRY_DIR).exists():
        shutil.rmtree(TEST_REGISTRY_DIR, ignore_errors=True)

def test_validation_gate_blocks_regressed_model():
    gate = TrustedValidationGate()
    
    # Degraded dummy model that predicts only 0s
    bad_model = DummyClassifier(strategy="constant", constant=0)
    bad_model.fit(gate.X_holdout, gate.y_holdout)

    passed, res = gate.evaluate_and_gate(
        bad_model, "candidate_degraded", active_baseline_metrics={"f1_score": 0.99}
    )
    assert passed is False
    assert res.passed is False
    assert res.block_reason is not None
    assert "fell below minimum acceptable threshold" in res.block_reason or "regression" in res.block_reason

def test_model_registry_promotion_and_rollback():
    registry = ModelRegistry(registry_dir=TEST_REGISTRY_DIR)

    from sklearn.ensemble import RandomForestClassifier
    m1 = RandomForestClassifier(n_estimators=10, random_state=42).fit([[1, 2], [3, 4]], [0, 1])
    m2 = RandomForestClassifier(n_estimators=10, random_state=99).fit([[1, 2], [3, 4]], [0, 1])

    v1 = registry.register_and_promote(m1, {"f1_score": 0.95})
    assert v1 == "v1.0.0"

    v2 = registry.register_and_promote(m2, {"f1_score": 0.97})
    assert v2 == "v1.1.0"

    active_m, active_meta = registry.get_active_model()
    assert active_meta["version"] == "v1.1.0"

    # Execute Rollback
    success, msg = registry.rollback()
    assert success is True
    
    active_m_after, active_meta_after = registry.get_active_model()
    assert active_meta_after["version"] == "v1.0.0"
    assert active_meta_after["status"] == "ACTIVE"
