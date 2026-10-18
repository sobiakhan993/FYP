"""
Data Preprocessing and Splitting Pipeline
Follows strict academic guidelines to prevent data leakage:
1. Load raw dataset and verify integrity (missing values, duplicates, constant columns).
2. Split into Train (70%), Validation (15%), and Test (15%) with fixed random seed.
3. Fit scaler ONLY on the Training set, then transform Val and Test.
4. Save processed datasets and scaler artifact.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

def preprocess_and_split(raw_path: str = 'data/raw/cloud_ransomware_raw.csv',
                         output_dir: str = 'data/processed',
                         random_state: int = 42):
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Reading raw dataset from: {raw_path}")
    df = pd.read_csv(raw_path)
    
    # 1. Exploratory Data Audit
    print(f"[*] Raw shape: {df.shape}")
    missing_count = df.isnull().sum().sum()
    print(f"[*] Total missing values: {missing_count}")
    duplicates_count = df.duplicated().sum()
    print(f"[*] Total duplicate rows: {duplicates_count}")
    if duplicates_count > 0:
        df = df.drop_duplicates()
        print(f"[*] Deduplicated shape: {df.shape}")
        
    features = [
        'files_modified_rate', 'files_renamed_rate', 'files_deleted_rate',
        'mean_entropy', 'max_entropy', 'extension_changes',
        'disk_read_bytes_sec', 'disk_write_bytes_sec', 'cpu_percent',
        'network_bytes_sec'
    ]
    target = 'label'
    
    # Drop constant columns if any
    non_constant = [col for col in features if df[col].nunique() > 1]
    features = non_constant
    
    X = df[features]
    y = df[target]
    
    # 2. Split 70% Train, 15% Val, 15% Test (stratified by label)
    # First split 70% train vs 30% temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=random_state, stratify=y
    )
    # Then split 30% temp equally into 15% val and 15% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=random_state, stratify=y_temp
    )
    
    print(f"[*] Train set shape: {X_train.shape} (Benign: {(y_train==0).sum()}, Attack: {(y_train==1).sum()})")
    print(f"[*] Val set shape:   {X_val.shape} (Benign: {(y_val==0).sum()}, Attack: {(y_val==1).sum()})")
    print(f"[*] Test set shape:  {X_test.shape} (Benign: {(y_test==0).sum()}, Attack: {(y_test==1).sum()})")
    
    # 3. Fit Scaler ONLY on Training data to prevent data leakage
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=features, index=X_train.index)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=features, index=X_val.index)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=features, index=X_test.index)
    
    # Save scaler
    scaler_path = os.path.join(output_dir, 'scaler.joblib')
    joblib.dump(scaler, scaler_path)
    print(f"[+] Fitted scaler saved to: {scaler_path}")
    
    # Combine back with labels and save both unscaled and scaled versions
    train_df = pd.concat([X_train, y_train], axis=1)
    val_df = pd.concat([X_val, y_val], axis=1)
    test_df = pd.concat([X_test, y_test], axis=1)
    
    train_scaled_df = pd.concat([X_train_scaled, y_train], axis=1)
    val_scaled_df = pd.concat([X_val_scaled, y_val], axis=1)
    test_scaled_df = pd.concat([X_test_scaled, y_test], axis=1)
    
    train_df.to_csv(os.path.join(output_dir, 'train_raw.csv'), index=False)
    val_df.to_csv(os.path.join(output_dir, 'val_raw.csv'), index=False)
    test_df.to_csv(os.path.join(output_dir, 'test_raw.csv'), index=False)
    
    train_scaled_df.to_csv(os.path.join(output_dir, 'train.csv'), index=False)
    val_scaled_df.to_csv(os.path.join(output_dir, 'val.csv'), index=False)
    test_scaled_df.to_csv(os.path.join(output_dir, 'test.csv'), index=False)
    
    # Save a trusted validation set (strictly clean ground truth for poisoning gating)
    val_scaled_df.to_csv(os.path.join(output_dir, 'trusted_validation.csv'), index=False)
    
    print("[+] All split datasets saved to data/processed/")
    return train_scaled_df, val_scaled_df, test_scaled_df

if __name__ == '__main__':
    preprocess_and_split()
