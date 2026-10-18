"""
Unit Tests for Telemetry and Feature Extraction Pipeline
"""

import unittest
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.monitoring.sandbox_simulator import calculate_shannon_entropy
from src.collection.event_consumer import EventConsumer

class TestFeaturePipeline(unittest.TestCase):
    def setUp(self):
        self.consumer = EventConsumer()

    def test_shannon_entropy_zero_on_empty(self):
        self.assertEqual(calculate_shannon_entropy(b""), 0.0)

    def test_shannon_entropy_low_on_uniform_text(self):
        # Repetitive plain text has low entropy (< 4.0)
        plain_text = b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"
        entropy = calculate_shannon_entropy(plain_text)
        self.assertLess(entropy, 3.0)

    def test_shannon_entropy_high_on_random_bytes(self):
        # Cryptographic random bytes have high entropy (~7.8 to 8.0)
        random_bytes = os.urandom(4096)
        entropy = calculate_shannon_entropy(random_bytes)
        self.assertGreater(entropy, 7.8)

    def test_window_feature_aggregation(self):
        mock_events = [
            {'event_type': 'modify', 'file_path': 'file1.txt', 'entropy': 3.2, 'timestamp': 1000},
            {'event_type': 'modify', 'file_path': 'file2.txt', 'entropy': 3.4, 'timestamp': 1005},
            {'event_type': 'modify', 'file_path': 'file2.txt', 'entropy': 3.4, 'timestamp': 1005}, # Duplicate
            {'event_type': 'rename_encrypted', 'file_path': 'file3.locked', 'old_extension': '.docx', 'file_extension': '.locked', 'entropy': 7.92, 'timestamp': 1010}
        ]
        features = self.consumer.aggregate_window_features(mock_events, window_duration=60.0)
        self.assertEqual(features['extension_changes'], 1)
        self.assertAlmostEqual(features['max_entropy'], 7.92, places=2)
        self.assertGreater(features['files_modified_rate'], 0)

if __name__ == '__main__':
    unittest.main()
