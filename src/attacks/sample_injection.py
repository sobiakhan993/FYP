"""
Controlled Sample-Injection Attack Generator
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Injects crafted, perturbed records into the training stream to test whether
the IDS model boundary can be distorted without immediate detection.
"""

from typing import Dict, Any, Tuple, List
import numpy as np
import pandas as pd
from src.common.logger import get_logger

logger = get_logger("SampleInjectionAttack")

class SampleInjectionAttacker:
    def __init__(self, feature_cols: List[str], target_label_col: str = "label", random_seed: int = 42):
        self.feature_cols = feature_cols
        self.target_label_col = target_label_col
        self.random_seed = random_seed

    def apply_attack(
        self,
        df: pd.DataFrame,
        poison_rate: float = 0.10,
        perturbation_std: float = 0.35,
        inject_label: int = 0 # Injected malicious-looking points labeled as Benign
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Synthesizes and injects perturbed points derived from existing distributions.
        Returns the combined DataFrame and separate provenance manifest.
        """
        rng = np.random.default_rng(self.random_seed)
        raw_count = round(len(df) * poison_rate)
        n_injected = max(1, int(raw_count)) if poison_rate > 0 else 0
        
        # Select base samples from opposite class to perturb
        base_candidates = df[df[self.target_label_col] == (1 - inject_label)]
        if len(base_candidates) == 0:
            base_candidates = df

        sampled_base = base_candidates.sample(n=n_injected, replace=True, random_state=self.random_seed)
        injected_features = sampled_base[self.feature_cols].values + rng.normal(
            loc=0.0, scale=perturbation_std, size=(n_injected, len(self.feature_cols))
        )

        injected_df = pd.DataFrame(injected_features, columns=self.feature_cols)
        injected_df[self.target_label_col] = inject_label
        injected_df["is_poisoned"] = True

        df_clean = df.copy()
        df_clean["is_poisoned"] = False

        combined_df = pd.concat([df_clean, injected_df], ignore_index=True)
        # Note the indices of the injected records
        injected_indices = list(range(len(df_clean), len(combined_df)))

        manifest = {
            "attack_type": "sample_injection",
            "poison_rate": poison_rate,
            "random_seed": self.random_seed,
            "clean_records": len(df),
            "injected_count": n_injected,
            "total_records": len(combined_df),
            "inject_label": inject_label,
            "poisoned_indices": injected_indices
        }

        logger.info(
            f"Sample injection applied: injected {n_injected} crafted records ({poison_rate:.1%}) with label {inject_label}"
        )
        return combined_df, manifest

if __name__ == "__main__":
    df = pd.DataFrame({
        "feat1": np.random.randn(50),
        "feat2": np.random.randn(50),
        "label": [0]*40 + [1]*10
    })
    attacker = SampleInjectionAttacker(feature_cols=["feat1", "feat2"])
    out_df, meta = attacker.apply_attack(df, poison_rate=0.10)
    print("Combined total:", len(out_df), "Injected:", meta["injected_count"])
