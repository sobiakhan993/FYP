"""
Unit Tests for Poisoning Sanitization and Retraining Gating Module
"""

import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from src.poisoning.poison_sanitizer import PoisoningSanitizer

class TestPoisoningSanitizer(unittest.TestCase):
    def setUp(self):
        self.sanitizer = PoisoningSanitizer(k_neighbors=5, lof_contamination=0.05)

    def test_clean_data_sanitization_minimal_false_flags(self):
        # On clean copy, false flags should be < 3%
        clean_path = 'data/poisoned/train_clean_copy.csv'
        if os.path.exists(clean_path):
            clean_df, report = self.sanitizer.inspect_and_sanitize(clean_path)
            total = report['total_samples_inspected']
            flagged = report['poisoned_samples_flagged']
            false_rate = (flagged / total) * 100.0
            self.assertLess(false_rate, 3.0)

    def test_gated_retraining_blocks_corrupted_model(self):
        # Create heavily poisoned synthetic dataset (100% labels flipped)
        clean_df = pd.read_csv('data/processed/train.csv').head(200).copy()
        clean_df['label'] = 1 - clean_df['label'] # Fully corrupted
        
        gate_summary = self.sanitizer.validate_and_gate_retraining(
            clean_df, trusted_val_path='data/processed/trusted_validation.csv'
        )
        self.assertEqual(gate_summary['status'], 'BLOCKED_DUE_TO_REGRESSION')
        self.assertFalse(gate_summary['deployment_allowed'])

if __name__ == '__main__':
    unittest.main()
