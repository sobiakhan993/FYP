"""
Dataset Generator for Cloud Workload Behavioral Telemetry
Generates high-fidelity cloud telemetry dataset reflecting both benign cloud workloads
(web servers, batch processing, database queries, compression backups) and ransomware
attack campaigns (rapid cryptors, slow/stealth cryptors, wiper-style encryption).
"""

import os
import numpy as np
import pandas as pd

def generate_cloud_workload_dataset(n_samples: int = 5000, random_state: int = 42) -> pd.DataFrame:
    np.random.seed(random_state)
    
    # 70% benign cloud operations, 30% ransomware attacks
    n_benign = int(n_samples * 0.70)
    n_attack = n_samples - n_benign
    
    # ----------------- BENIGN SAMPLES -----------------
    # 1. Normal web/database activity: moderate modifications, normal low entropy, 0 renames
    n_b1 = int(n_benign * 0.50)
    b1_mod = np.random.uniform(1.0, 15.0, n_b1)
    b1_ren = np.random.uniform(0.0, 1.0, n_b1)
    b1_del = np.random.uniform(0.0, 2.0, n_b1)
    b1_mean_ent = np.random.normal(3.8, 0.6, n_b1)
    b1_max_ent = b1_mean_ent + np.random.uniform(0.2, 0.8, n_b1)
    b1_ext_chg = np.random.poisson(0.1, n_b1)
    b1_read = np.random.uniform(100_000, 3_000_000, n_b1)
    b1_write = np.random.uniform(50_000, 2_000_000, n_b1)
    b1_cpu = np.random.uniform(5.0, 35.0, n_b1)
    b1_net = np.random.uniform(20_000, 1_500_000, n_b1)
    
    # 2. Benign heavy backup / compression: higher entropy (due to zip/gzip), high read/write, high CPU
    # Crucial to train model not to false-alarm on legitimate zip operations!
    n_b2 = int(n_benign * 0.30)
    b2_mod = np.random.uniform(10.0, 40.0, n_b2)
    b2_ren = np.random.uniform(0.0, 2.0, n_b2)
    b2_del = np.random.uniform(0.0, 3.0, n_b2)
    b2_mean_ent = np.random.normal(6.2, 0.4, n_b2)  # compression has moderately high entropy
    b2_max_ent = np.clip(b2_mean_ent + np.random.uniform(0.3, 0.9, n_b2), 4.0, 7.3)
    b2_ext_chg = np.random.poisson(0.5, n_b2) # maybe .tar.gz created, but not mass extension alteration
    b2_read = np.random.uniform(5_000_000, 25_000_000, n_b2)
    b2_write = np.random.uniform(4_000_000, 20_000_000, n_b2)
    b2_cpu = np.random.uniform(40.0, 85.0, n_b2)
    b2_net = np.random.uniform(100_000, 5_000_000, n_b2)

    # 3. Software build / log rotation: high file count, low entropy, low CPU
    n_b3 = n_benign - n_b1 - n_b2
    b3_mod = np.random.uniform(20.0, 60.0, n_b3)
    b3_ren = np.random.uniform(2.0, 8.0, n_b3)
    b3_del = np.random.uniform(5.0, 15.0, n_b3)
    b3_mean_ent = np.random.normal(3.2, 0.5, n_b3)
    b3_max_ent = b3_mean_ent + np.random.uniform(0.4, 1.0, n_b3)
    b3_ext_chg = np.random.poisson(0.3, n_b3)
    b3_read = np.random.uniform(1_000_000, 8_000_000, n_b3)
    b3_write = np.random.uniform(1_000_000, 6_000_000, n_b3)
    b3_cpu = np.random.uniform(15.0, 50.0, n_b3)
    b3_net = np.random.uniform(50_000, 800_000, n_b3)

    benign_df = pd.DataFrame({
        'files_modified_rate': np.concatenate([b1_mod, b2_mod, b3_mod]),
        'files_renamed_rate': np.concatenate([b1_ren, b2_ren, b3_ren]),
        'files_deleted_rate': np.concatenate([b1_del, b2_del, b3_del]),
        'mean_entropy': np.clip(np.concatenate([b1_mean_ent, b2_mean_ent, b3_mean_ent]), 1.0, 7.4),
        'max_entropy': np.clip(np.concatenate([b1_max_ent, b2_max_ent, b3_max_ent]), 1.5, 7.45),
        'extension_changes': np.concatenate([b1_ext_chg, b2_ext_chg, b3_ext_chg]),
        'disk_read_bytes_sec': np.concatenate([b1_read, b2_read, b3_read]),
        'disk_write_bytes_sec': np.concatenate([b1_write, b2_write, b3_write]),
        'cpu_percent': np.clip(np.concatenate([b1_cpu, b2_cpu, b3_cpu]), 1.0, 95.0),
        'network_bytes_sec': np.concatenate([b1_net, b2_net, b3_net]),
        'label': 0  # Benign
    })

    # ----------------- ATTACK SAMPLES (RANSOMWARE) -----------------
    # 1. Fast cryptor (e.g. LockBit, WannaCry): massive modification rate, near theoretical max entropy (>7.8), mass extension renames
    n_a1 = int(n_attack * 0.60)
    a1_mod = np.random.uniform(50.0, 200.0, n_a1)
    a1_ren = np.random.uniform(30.0, 150.0, n_a1)
    a1_del = np.random.uniform(5.0, 30.0, n_a1)
    a1_mean_ent = np.random.normal(7.75, 0.12, n_a1)
    a1_max_ent = np.clip(a1_mean_ent + np.random.uniform(0.1, 0.22, n_a1), 7.7, 7.999)
    a1_ext_chg = np.random.randint(25, 180, n_a1)
    a1_read = np.random.uniform(8_000_000, 35_000_000, n_a1)
    a1_write = np.random.uniform(10_000_000, 40_000_000, n_a1)
    a1_cpu = np.random.uniform(60.0, 99.0, n_a1)
    a1_net = np.random.uniform(50_000, 2_000_000, n_a1)

    # 2. Slow/stealth cryptor: lower file modification rate, but very high entropy and clear extension alterations
    n_a2 = int(n_attack * 0.30)
    a2_mod = np.random.uniform(8.0, 35.0, n_a2)
    a2_ren = np.random.uniform(6.0, 25.0, n_a2)
    a2_del = np.random.uniform(1.0, 10.0, n_a2)
    a2_mean_ent = np.random.normal(7.68, 0.15, n_a2)
    a2_max_ent = np.clip(a2_mean_ent + np.random.uniform(0.12, 0.25, n_a2), 7.6, 7.995)
    a2_ext_chg = np.random.randint(6, 30, n_a2)
    a2_read = np.random.uniform(1_500_000, 8_000_000, n_a2)
    a2_write = np.random.uniform(1_800_000, 10_000_000, n_a2)
    a2_cpu = np.random.uniform(25.0, 65.0, n_a2)
    a2_net = np.random.uniform(10_000, 800_000, n_a2)

    # 3. Intermittent encryption / wiper attack: destructive deletion and high entropy writes
    n_a3 = n_attack - n_a1 - n_a2
    a3_mod = np.random.uniform(40.0, 120.0, n_a3)
    a3_ren = np.random.uniform(10.0, 60.0, n_a3)
    a3_del = np.random.uniform(20.0, 80.0, n_a3) # mass deletion of shadow copies/backups
    a3_mean_ent = np.random.normal(7.82, 0.10, n_a3)
    a3_max_ent = np.clip(a3_mean_ent + np.random.uniform(0.08, 0.16, n_a3), 7.8, 7.999)
    a3_ext_chg = np.random.randint(15, 90, n_a3)
    a3_read = np.random.uniform(5_000_000, 20_000_000, n_a3)
    a3_write = np.random.uniform(8_000_000, 25_000_000, n_a3)
    a3_cpu = np.random.uniform(50.0, 95.0, n_a3)
    a3_net = np.random.uniform(200_000, 3_000_000, n_a3)

    attack_df = pd.DataFrame({
        'files_modified_rate': np.concatenate([a1_mod, a2_mod, a3_mod]),
        'files_renamed_rate': np.concatenate([a1_ren, a2_ren, a3_ren]),
        'files_deleted_rate': np.concatenate([a1_del, a2_del, a3_del]),
        'mean_entropy': np.clip(np.concatenate([a1_mean_ent, a2_mean_ent, a3_mean_ent]), 7.45, 7.999),
        'max_entropy': np.clip(np.concatenate([a1_max_ent, a2_max_ent, a3_max_ent]), 7.55, 8.00),
        'extension_changes': np.concatenate([a1_ext_chg, a2_ext_chg, a3_ext_chg]),
        'disk_read_bytes_sec': np.concatenate([a1_read, a2_read, a3_read]),
        'disk_write_bytes_sec': np.concatenate([a1_write, a2_write, a3_write]),
        'cpu_percent': np.clip(np.concatenate([a1_cpu, a2_cpu, a3_cpu]), 20.0, 100.0),
        'network_bytes_sec': np.concatenate([a1_net, a2_net, a3_net]),
        'label': 1  # Ransomware
    })

    full_df = pd.concat([benign_df, attack_df], ignore_index=True)
    # Shuffle the dataset cleanly
    full_df = full_df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    return full_df

if __name__ == '__main__':
    os.makedirs('data/raw', exist_ok=True)
    df = generate_cloud_workload_dataset(n_samples=5000, random_state=42)
    output_path = 'data/raw/cloud_ransomware_raw.csv'
    df.to_csv(output_path, index=False)
    print(f"[+] Successfully generated raw dataset: {output_path}")
    print(f"[+] Total samples: {len(df)} (Benign: {(df['label']==0).sum()}, Attack: {(df['label']==1).sum()})")
