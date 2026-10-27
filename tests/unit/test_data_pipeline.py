"""
Unit Tests: Data Pipeline & Anti-Leakage Verification
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import pytest
import pandas as pd
import numpy as np
from pathlib import Path
from src.data.stream_replayer import SchemaValidator, StreamReplayer
from src.attacks.label_flip import LabelFlipAttacker
from src.attacks.sample_injection import SampleInjectionAttacker

def test_data_splits_exist_and_non_empty():
    paths = [
        "data/processed/train.csv",
        "data/processed/val.csv",
        "data/processed/trusted_validation.csv"
    ]
    for p in paths:
        assert Path(p).exists(), f"Split missing: {p}"
        df = pd.read_csv(p)
        assert len(df) > 0, f"Split empty: {p}"
        assert "label" in df.columns

def test_schema_validator():
    features = ["flow_duration", "total_fwd_packets"]
    validator = SchemaValidator(features)
    
    valid_rec = {"flow_duration": 1.2, "total_fwd_packets": 5, "label": 0}
    is_valid, msg = validator.validate_record(valid_rec)
    assert is_valid is True

    invalid_rec = {"flow_duration": None, "total_fwd_packets": 5}
    is_valid, msg = validator.validate_record(invalid_rec)
    assert is_valid is False

def test_label_flipping_attack():
    df = pd.DataFrame({
        "flow_duration": [1.0, 2.0, 3.0, 4.0, 5.0],
        "label": [1, 1, 1, 1, 0]
    })
    attacker = LabelFlipAttacker(random_seed=42)
    p_df, meta = attacker.apply_attack(df, poison_rate=0.40)
    assert meta["flipped_count"] == 2
    assert p_df["is_poisoned"].sum() == 2

def test_sample_injection_attack():
    df = pd.DataFrame({
        "f1": [1.0, 2.0, 3.0],
        "f2": [4.0, 5.0, 6.0],
        "label": [0, 0, 1]
    })
    attacker = SampleInjectionAttacker(feature_cols=["f1", "f2"], random_seed=42)
    p_df, meta = attacker.apply_attack(df, poison_rate=0.33)
    assert len(p_df) == 4
    assert meta["injected_count"] == 1
