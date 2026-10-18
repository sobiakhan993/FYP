"""
Unit Tests for Threat Detection Engine and Score Combiner
"""

import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.detection.detector_engine import ThreatDetectorEngine

class TestThreatDetectorEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatDetectorEngine(load_models=True)

    def test_benign_workload_scoring(self):
        # Normal web/db activity
        benign_sample = {
            'files_modified_rate': 4.5,
            'files_renamed_rate': 0.2,
            'files_deleted_rate': 0.1,
            'mean_entropy': 3.45,
            'max_entropy': 3.90,
            'extension_changes': 0,
            'disk_read_bytes_sec': 500000.0,
            'disk_write_bytes_sec': 300000.0,
            'cpu_percent': 15.0,
            'network_bytes_sec': 20000.0
        }
        res = self.engine.score_feature_vector(benign_sample)
        self.assertEqual(res['verdict'], 'benign')
        self.assertEqual(res['severity'], 'low')
        self.assertFalse(res['alert_required'])
        self.assertLess(res['latency_ms'], 100.0)

    def test_ransomware_attack_scoring(self):
        # High entropy, mass extension changes, elevated modification
        attack_sample = {
            'files_modified_rate': 95.0,
            'files_renamed_rate': 80.0,
            'files_deleted_rate': 15.0,
            'mean_entropy': 7.88,
            'max_entropy': 7.99,
            'extension_changes': 50,
            'disk_read_bytes_sec': 12000000.0,
            'disk_write_bytes_sec': 20000000.0,
            'cpu_percent': 85.0,
            'network_bytes_sec': 500000.0
        }
        res = self.engine.score_feature_vector(attack_sample)
        self.assertEqual(res['verdict'], 'ransomware')
        self.assertEqual(res['severity'], 'critical')
        self.assertTrue(res['alert_required'])
        self.assertGreaterEqual(res['composite_score'], 0.90)

    def test_inference_latency_under_50ms(self):
        sample = {
            'files_modified_rate': 10.0, 'files_renamed_rate': 0.0, 'files_deleted_rate': 0.0,
            'mean_entropy': 4.0, 'max_entropy': 4.5, 'extension_changes': 0,
            'disk_read_bytes_sec': 1000.0, 'disk_write_bytes_sec': 1000.0,
            'cpu_percent': 10.0, 'network_bytes_sec': 1000.0
        }
        res = self.engine.score_feature_vector(sample)
        self.assertLess(res['latency_ms'], 50.0)

if __name__ == '__main__':
    unittest.main()
