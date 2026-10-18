"""
Poisoning Attack Simulator
Implements training data poisoning attacks:
1. Label Flipping Attacks (at 5%, 10%, 20% poisoning rates).
   - Inverts attack samples (label 1 -> 0) to blind the classifier to ransomware patterns.
2. Injected / Crafted Backdoor Samples (at 10% rate).
   - Injects crafted feature vectors with high entropy but labeled as benign.
3. Maintains an untouched clean copy as ground truth.
4. Generates a poisoning manifest recording ground-truth indices of contaminated points.
"""

import os
import json
import pandas as pd
import numpy as np

def simulate_poisoning(train_path: str = 'data/processed/train.csv',
                       output_dir: str = 'data/poisoned',
                       random_state: int = 42):
    os.makedirs(output_dir, exist_ok=True)
    np.random.seed(random_state)
    
    df = pd.read_csv(train_path)
    total_samples = len(df)
    print(f"[*] Base training dataset has {total_samples} samples.")
    
    # Save untouched clean ground truth copy
    clean_copy_path = os.path.join(output_dir, 'train_clean_copy.csv')
    df.to_csv(clean_copy_path, index=False)
    print(f"[+] Saved ground truth clean copy to: {clean_copy_path}")
    
    manifest = {
        'total_samples': total_samples,
        'clean_copy': clean_copy_path,
        'experiments': {}
    }
    
    # ---------------- 1. LABEL FLIPPING ATTACKS (5%, 10%, 20%) ----------------
    rates = [0.05, 0.10, 0.20]
    for rate in rates:
        poisoned_df = df.copy()
        n_poison = int(total_samples * rate)
        
        # In a realistic poisoning attack against an IDS/ransomware detector,
        # the attacker aims to flip ransomware attack samples (label 1) into benign (label 0),
        # so that when the model is retrained, it ceases to detect ransomware!
        attack_indices = poisoned_df[poisoned_df['label'] == 1].index.tolist()
        
        if len(attack_indices) >= n_poison:
            flipped_indices = np.random.choice(attack_indices, size=n_poison, replace=False).tolist()
        else:
            # If rate is large, flip some benign as well
            other_indices = poisoned_df[poisoned_df['label'] == 0].index.tolist()
            flipped_indices = attack_indices + np.random.choice(other_indices, size=n_poison-len(attack_indices), replace=False).tolist()
        
        # Perform label flip
        poisoned_df.loc[flipped_indices, 'label'] = 1 - poisoned_df.loc[flipped_indices, 'label']
        
        rate_int = int(rate * 100)
        out_filename = f'train_poisoned_label_flip_{rate_int}pct.csv'
        out_filepath = os.path.join(output_dir, out_filename)
        poisoned_df.to_csv(out_filepath, index=False)
        
        manifest['experiments'][f'label_flip_{rate_int}pct'] = {
            'file': out_filepath,
            'poisoning_rate': rate,
            'poisoned_samples_count': n_poison,
            'flipped_indices': [int(i) for i in flipped_indices]
        }
        print(f"[+] Created {rate_int}% label-flipped dataset: {out_filepath} ({n_poison} poisoned samples)")
        
    # ---------------- 2. INJECTED CRAFTED SAMPLES (10%) ----------------
    injected_df = df.copy()
    n_injected = int(total_samples * 0.10)
    
    # Crafted samples have high entropy and high rename rates, but mislabeled as benign (0)
    feature_cols = [c for c in df.columns if c != 'label']
    crafted_features = []
    
    # We sample attack distributions but force label = 0
    attack_samples = df[df['label'] == 1][feature_cols]
    chosen_samples = attack_samples.sample(n=n_injected, replace=True, random_state=random_state)
    
    # Add subtle jitter to evade naive duplicate filters
    jitter = np.random.normal(0, 0.05, chosen_samples.shape)
    crafted_data = chosen_samples.values + jitter
    crafted_df = pd.DataFrame(crafted_data, columns=feature_cols)
    crafted_df['label'] = 0 # Poison: labeled as benign!
    
    injected_full_df = pd.concat([df, crafted_df], ignore_index=True)
    injected_indices = list(range(len(df), len(injected_full_df)))
    
    injected_filepath = os.path.join(output_dir, 'train_poisoned_injected_10pct.csv')
    injected_full_df.to_csv(injected_filepath, index=False)
    
    manifest['experiments']['injected_10pct'] = {
        'file': injected_filepath,
        'poisoning_rate': 0.10,
        'poisoned_samples_count': n_injected,
        'injected_indices': [int(i) for i in injected_indices]
    }
    print(f"[+] Created 10% injected crafted dataset: {injected_filepath} ({n_injected} injected samples)")
    
    manifest_path = os.path.join(output_dir, 'poisoning_manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Poisoning manifest saved to: {manifest_path}")

if __name__ == '__main__':
    simulate_poisoning()
