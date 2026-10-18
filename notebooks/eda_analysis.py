"""
Exploratory Data Analysis (EDA) Script
Performs statistical profiling, class balance verification, feature distributions,
and correlation matrix analysis on the raw and processed cloud workload dataset.
"""

import os
import pandas as pd
import numpy as np

def run_eda(data_path: str = 'data/raw/cloud_ransomware_raw.csv', output_dir: str = 'docs/phase3_eda'):
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Commencing Exploratory Data Analysis on: {data_path}")
    df = pd.read_csv(data_path)
    
    print("\n--- 1. DATASET SHAPE & TYPES ---")
    print(f"Rows: {df.shape[0]}, Columns: {df.shape[1]}")
    print(df.dtypes)
    
    print("\n--- 2. CLASS BALANCE ---")
    counts = df['label'].value_counts()
    percentages = df['label'].value_counts(normalize=True) * 100
    for label, count in counts.items():
        name = "Benign" if label == 0 else "Ransomware"
        print(f"  Class {label} ({name}): {count} samples ({percentages[label]:.2f}%)")
        
    print("\n--- 3. MISSING VALUES & NULLS ---")
    missing = df.isnull().sum()
    print(missing[missing > 0] if missing.sum() > 0 else "  Zero missing values detected.")
    
    print("\n--- 4. DESCRIPTIVE STATISTICS (BY CLASS) ---")
    benign_stats = df[df['label'] == 0].describe().T[['mean', 'std', 'min', 'max']]
    attack_stats = df[df['label'] == 1].describe().T[['mean', 'std', 'min', 'max']]
    print("\n[Benign Workloads - Key Means]")
    print(benign_stats[['mean', 'max']])
    print("\n[Ransomware Attacks - Key Means]")
    print(attack_stats[['mean', 'max']])
    
    print("\n--- 5. CORRELATION WITH TARGET LABEL ---")
    correlations = df.corr()['label'].sort_values(ascending=False)
    print(correlations)
    
    # Save text report
    report_file = os.path.join(output_dir, 'eda_summary_report.txt')
    with open(report_file, 'w') as f:
        f.write("=== EXPLORATORY DATA ANALYSIS (EDA) REPORT ===\n\n")
        f.write(f"Total Samples: {len(df)}\n")
        f.write(f"Benign Samples: {counts.get(0, 0)} ({percentages.get(0, 0):.2f}%)\n")
        f.write(f"Ransomware Samples: {counts.get(1, 0)} ({percentages.get(1, 0):.2f}%)\n\n")
        f.write("Feature Correlations with Target Label:\n")
        f.write(correlations.to_string())
        f.write("\n\nDescriptive Statistics:\n")
        f.write(df.describe().to_string())
        
    print(f"\n[+] EDA summary report exported to: {report_file}")

if __name__ == '__main__':
    run_eda()
