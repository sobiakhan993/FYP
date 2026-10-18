"""
Event Consumer & Sliding-Window Feature Extraction Pipeline
Ingests raw event telemetry, performs deduplication, aligns timestamps,
and computes sliding-window feature rows ready for ML scoring and database storage.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import time
import psutil
from datetime import datetime
from typing import List, Dict, Any, Optional
from src.collection.database import get_db_connection, insert_feature_row

class EventConsumer:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._last_disk = psutil.disk_io_counters()
        self._last_net = psutil.net_io_counters()
        self._last_time = time.time()

    def get_system_rates(self):
        now = time.time()
        elapsed = max(now - self._last_time, 0.001)
        
        curr_disk = psutil.disk_io_counters()
        curr_net = psutil.net_io_counters()
        
        read_rate = (curr_disk.read_bytes - self._last_disk.read_bytes) / elapsed
        write_rate = (curr_disk.write_bytes - self._last_disk.write_bytes) / elapsed
        net_rate = (curr_net.bytes_sent + curr_net.bytes_recv - self._last_net.bytes_sent - self._last_net.bytes_recv) / elapsed
        cpu = psutil.cpu_percent(interval=None)
        
        self._last_disk = curr_disk
        self._last_net = curr_net
        self._last_time = now
        
        return {
            'disk_read_bytes_sec': max(round(read_rate, 2), 0.0),
            'disk_write_bytes_sec': max(round(write_rate, 2), 0.0),
            'cpu_percent': round(cpu, 2),
            'network_bytes_sec': max(round(net_rate, 2), 0.0)
        }

    def aggregate_window_features(self, events: List[Dict[str, Any]], window_duration: float = 60.0) -> Dict[str, Any]:
        """Aggregates a list of raw events into a 60-second window feature vector."""
        if not events:
            sys_metrics = self.get_system_rates()
            now_iso = datetime.utcnow().isoformat()
            return {
                'window_start': now_iso,
                'window_end': now_iso,
                'files_modified_rate': 0.0,
                'files_renamed_rate': 0.0,
                'files_deleted_rate': 0.0,
                'mean_entropy': 0.0,
                'max_entropy': 0.0,
                'extension_changes': 0,
                'disk_read_bytes_sec': sys_metrics['disk_read_bytes_sec'],
                'disk_write_bytes_sec': sys_metrics['disk_write_bytes_sec'],
                'cpu_percent': sys_metrics['cpu_percent'],
                'network_bytes_sec': sys_metrics['network_bytes_sec'],
                'true_label': 'benign'
            }
            
        # Deduplication
        unique_events = {}
        for ev in events:
            key = (ev.get('event_type'), ev.get('file_path'), round(float(ev.get('timestamp', 0)), 1) if isinstance(ev.get('timestamp'), (int, float)) else ev.get('timestamp'))
            unique_events[key] = ev
        clean_events = list(unique_events.values())
        
        # Count types
        mod_count = sum(1 for e in clean_events if e.get('event_type') in ['modify', 'write'])
        ren_count = sum(1 for e in clean_events if e.get('event_type') in ['rename', 'rename_encrypted'])
        del_count = sum(1 for e in clean_events if e.get('event_type') == 'delete')
        
        # Scaling to per-minute rate
        rate_multiplier = 60.0 / max(window_duration, 1.0)
        files_modified_rate = round(mod_count * rate_multiplier, 2)
        files_renamed_rate = round(ren_count * rate_multiplier, 2)
        files_deleted_rate = round(del_count * rate_multiplier, 2)
        
        # Entropy calculations
        entropies = [float(e.get('entropy', 0.0)) for e in clean_events if float(e.get('entropy', 0.0)) > 0]
        mean_entropy = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
        max_entropy = round(max(entropies), 4) if entropies else 0.0
        
        # Extension changes
        ext_changes = sum(1 for e in clean_events if e.get('old_extension') and e.get('file_extension') and e.get('old_extension') != e.get('file_extension'))
        if ext_changes == 0:
            ext_changes = sum(1 for e in clean_events if e.get('file_extension') in ['.locked', '.crypto', '.enc', '.crypted'])
            
        sys_metrics = self.get_system_rates()
        now_iso = datetime.utcnow().isoformat()
        
        feature_row = {
            'window_start': clean_events[0].get('timestamp', now_iso) if clean_events else now_iso,
            'window_end': clean_events[-1].get('timestamp', now_iso) if clean_events else now_iso,
            'files_modified_rate': files_modified_rate,
            'files_renamed_rate': files_renamed_rate,
            'files_deleted_rate': files_deleted_rate,
            'mean_entropy': mean_entropy,
            'max_entropy': max_entropy,
            'extension_changes': ext_changes,
            'disk_read_bytes_sec': sys_metrics['disk_read_bytes_sec'],
            'disk_write_bytes_sec': sys_metrics['disk_write_bytes_sec'],
            'cpu_percent': sys_metrics['cpu_percent'],
            'network_bytes_sec': sys_metrics['network_bytes_sec'],
            'true_label': 'ransomware' if ext_changes > 5 or max_entropy > 7.5 else 'benign'
        }
        
        return feature_row

    def process_and_store_window(self, events: List[Dict[str, Any]], window_duration: float = 60.0) -> int:
        feature_dict = self.aggregate_window_features(events, window_duration)
        row_id = insert_feature_row(feature_dict)
        return row_id

if __name__ == '__main__':
    consumer = EventConsumer()
    print("[*] Testing consumer window aggregation with simulated events...")
    sample_events = [
        {'event_type': 'modify', 'file_path': 'test1.docx', 'entropy': 7.92, 'timestamp': time.time()},
        {'event_type': 'rename_encrypted', 'file_path': 'test1.docx.locked', 'old_extension': '.docx', 'file_extension': '.locked', 'entropy': 7.95, 'timestamp': time.time()}
    ]
    feat = consumer.aggregate_window_features(sample_events, window_duration=5.0)
    print("[+] Computed Feature Row:")
    for k, v in feat.items():
        print(f"    {k}: {v}")
    row_id = consumer.process_and_store_window(sample_events, window_duration=5.0)
    print(f"[+] Successfully stored feature row in database with ID: {row_id}")
