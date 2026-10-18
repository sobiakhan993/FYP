"""
Dual-Engine Real-Time ML Detection Service and Score Combiner
1. Supervised Random Forest Classifier (trained on benign & ransomware patterns).
2. Unsupervised Isolation Forest Anomaly Detector (trained on normal profile).
3. Hybrid Score Combiner for joint verdict and severity classification.
4. Feature Attribution Engine for explainable threat signals.
5. Sub-millisecond inference latency benchmarking.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import time
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, f1_score, confusion_matrix, precision_score, recall_score

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'models'))
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.joblib')
RF_MODEL_PATH = os.path.join(MODELS_DIR, 'production_rf_v1.0.joblib')
ISO_MODEL_PATH = os.path.join(MODELS_DIR, 'production_isoforest_v1.0.joblib')

class ThreatDetectorEngine:
    def __init__(self, load_models: bool = True):
        self.rf_model = None
        self.iso_model = None
        self.scaler = None
        self.feature_names = [
            'files_modified_rate', 'files_renamed_rate', 'files_deleted_rate',
            'mean_entropy', 'max_entropy', 'extension_changes',
            'disk_read_bytes_sec', 'disk_write_bytes_sec', 'cpu_percent',
            'network_bytes_sec'
        ]
        if load_models and os.path.exists(RF_MODEL_PATH) and os.path.exists(ISO_MODEL_PATH):
            self.load()

    def train_and_tune(self, train_path: str = 'data/processed/train.csv',
                       val_path: str = 'data/processed/val.csv'):
        os.makedirs(MODELS_DIR, exist_ok=True)
        print("[*] Training and Tuning Dual Detection Engine...")
        
        train_df = pd.read_csv(train_path)
        X_train = train_df[self.feature_names]
        y_train = train_df['label']
        
        # 1. 5-Fold Stratified Cross Validation on Random Forest
        rf = RandomForestClassifier(n_estimators=150, max_depth=14, min_samples_split=4, random_state=42)
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(rf, X_train, y_train, cv=skf, scoring='f1')
        print(f"[+] 5-Fold Stratified Cross-Validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        rf.fit(X_train, y_train)
        self.rf_model = rf
        joblib.dump(rf, RF_MODEL_PATH)
        print(f"[+] Saved Production Random Forest to: {RF_MODEL_PATH}")
        
        # 2. Train Unsupervised Anomaly Detector on Normal profile
        normal_data = X_train[y_train == 0]
        iso = IsolationForest(n_estimators=120, contamination=0.08, random_state=42)
        iso.fit(normal_data)
        self.iso_model = iso
        joblib.dump(iso, ISO_MODEL_PATH)
        print(f"[+] Saved Production Isolation Forest to: {ISO_MODEL_PATH}")
        
        # Load scaler
        if os.path.exists(SCALER_PATH):
            self.scaler = joblib.load(SCALER_PATH)

    def load(self):
        self.rf_model = joblib.load(RF_MODEL_PATH)
        self.iso_model = joblib.load(ISO_MODEL_PATH)
        if os.path.exists(SCALER_PATH):
            self.scaler = joblib.load(SCALER_PATH)
        print("[+] Loaded production models into memory.")

    def explain_feature_importance(self, feature_vector: np.ndarray) -> List[Dict[str, Any]]:
        """Returns top feature contributions for the prediction."""
        if not hasattr(self.rf_model, 'feature_importances_'):
            return []
        importances = self.rf_model.feature_importances_
        # Normalize contributions
        ranked_idx = np.argsort(importances)[::-1]
        results = []
        for idx in ranked_idx[:4]:
            results.append({
                'feature': self.feature_names[idx],
                'importance_weight': round(float(importances[idx]), 4),
                'normalized_value': round(float(feature_vector[idx]), 3)
            })
        return results

    def score_feature_vector(self, feature_row: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes dual-engine inference on a feature row.
        Returns composite threat score, verdict, severity, and top signals.
        """
        if self.rf_model is None or self.iso_model is None:
            self.load()
            
        t0 = time.perf_counter()
        raw_vals = [float(feature_row.get(col, 0.0)) for col in self.feature_names]
        X_raw = np.array([raw_vals])
        
        # Scale if scaler exists
        if self.scaler is not None:
            X_scaled = self.scaler.transform(X_raw)
        else:
            X_scaled = X_raw
            
        # 1. Supervised Prediction
        rf_prob = float(self.rf_model.predict_proba(X_scaled)[0, 1])
        
        # 2. Unsupervised Anomaly Prediction
        iso_raw_score = float(self.iso_model.decision_function(X_scaled)[0])
        # Decision function: positive is normal inlier, negative is anomaly.
        # Normalize anomaly score to [0, 1] range where 1 is highest anomaly:
        iso_anomaly_prob = float(np.clip(0.5 - (iso_raw_score * 2.0), 0.0, 1.0))
        
        # 3. Score Combiner Logic
        # If supervised model has high confidence in ransomware, designated as ransomware.
        # If supervised model is unsure, but anomaly detector flags extreme outlier, flagged as zero-day suspicious.
        composite_score = round(max(rf_prob, 0.75 * iso_anomaly_prob), 4)
        
        if rf_prob >= 0.80:
            verdict = "ransomware"
            severity = "critical" if rf_prob >= 0.90 else "high"
        elif rf_prob >= 0.45 or iso_anomaly_prob >= 0.70:
            verdict = "suspicious_anomaly"
            severity = "medium"
        elif iso_anomaly_prob >= 0.50:
            verdict = "minor_deviation"
            severity = "low"
        else:
            verdict = "benign"
            severity = "low"
            
        latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        top_signals = self.explain_feature_importance(X_scaled[0])
        
        return {
            'verdict': verdict,
            'severity': severity,
            'composite_score': composite_score,
            'supervised_probability': round(rf_prob, 4),
            'anomaly_score': round(iso_anomaly_prob, 4),
            'raw_anomaly_decision': round(iso_raw_score, 4),
            'latency_ms': latency_ms,
            'top_signals': top_signals,
            'alert_required': severity in ['high', 'critical'] or verdict in ['ransomware', 'suspicious_anomaly']
        }

if __name__ == '__main__':
    engine = ThreatDetectorEngine(load_models=False)
    engine.train_and_tune()
    
    # Test sample inference latency
    test_sample = {
        'files_modified_rate': 85.0,
        'files_renamed_rate': 60.0,
        'files_deleted_rate': 10.0,
        'mean_entropy': 7.85,
        'max_entropy': 7.99,
        'extension_changes': 45,
        'disk_read_bytes_sec': 5000000.0,
        'disk_write_bytes_sec': 8000000.0,
        'cpu_percent': 78.5,
        'network_bytes_sec': 50000.0
    }
    result = engine.score_feature_vector(test_sample)
    print("\n[+] Inference Result on Ransomware Sample:")
    for k, v in result.items():
        print(f"    {k}: {v}")
