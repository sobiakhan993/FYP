"""
Controlled Label-Flipping Attack Generator
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Flips target class labels (e.g., inverting malicious flows from 1 to 0) to evaluate
the vulnerability of continuously retrained IDS models and benchmark the defense.
Ground-truth poison flags are recorded strictly separately for evaluation.
"""

import json
from pathlib import Path
from typing import Dict, Any, Tuple, List
import numpy as np
import pandas as pd
from src.common.logger import get_logger

logger = get_logger("LabelFlipAttack")

class LabelFlipAttacker:
    def __init__(self, target_label_col: str = "label", random_seed: int = 42):
        self.target_label_col = target_label_col
        self.random_seed = random_seed

    def apply_attack(
        self,
        df: pd.DataFrame,
        poison_rate: float = 0.10,
        source_class: int = 1, # Malicious flows
        target_class: int = 0  # Flipped to Benign to create blind spots
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Applies label flipping at the specified rate.
        Returns the poisoned DataFrame and a separate evaluation manifest.
        """
        df_poisoned = df.copy()
        rng = np.random.default_rng(self.random_seed)

        # Candidates eligible for flipping
        candidate_indices = df_poisoned[df_poisoned[self.target_label_col] == source_class].index.tolist()
        n_to_flip = int(len(df_poisoned) * poison_rate)
        n_to_flip = min(n_to_flip, len(candidate_indices))

        if n_to_flip == 0:
            logger.warning("Poison rate resulted in 0 samples to flip.")
            return df_poisoned, {"attack_type": "label_flip", "flipped_count": 0, "indices": []}

        flipped_indices = rng.choice(candidate_indices, size=n_to_flip, replace=False).tolist()
        
        # Apply the label flip
        df_poisoned.loc[flipped_indices, self.target_label_col] = target_class

        # Ground truth tracking for evaluation metrics ONLY
        df_poisoned["is_poisoned"] = False
        df_poisoned.loc[flipped_indices, "is_poisoned"] = True

        manifest = {
            "attack_type": "label_flipping",
            "poison_rate": poison_rate,
            "random_seed": self.random_seed,
            "total_records": len(df),
            "flipped_count": n_to_flip,
            "source_class": source_class,
            "target_class": target_class,
            "poisoned_indices": [int(i) for i in flipped_indices]
        }

        logger.info(
            f"Label-flipping applied: {n_to_flip}/{len(df)} records flipped ({poison_rate:.1%}) from class {source_class} to {target_class}"
        )
        return df_poisoned, manifest

if __name__ == "__main__":
    test_df = pd.DataFrame({"feat1": [1.0, 2.0, 3.0, 4.0], "label": [1, 1, 0, 1]})
    attacker = LabelFlipAttacker(random_seed=42)
    p_df, meta = attacker.apply_attack(test_df, poison_rate=0.50)
    print("Poisoned output:\n", p_df)
    print("Manifest:", meta)
