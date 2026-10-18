"""
Host Telemetry Monitoring Collector
Hooks filesystem events using Watchdog and captures system I/O using Psutil.
Calculates Shannon Entropy for modified files, tracks process metrics,
and pushes serialized telemetry events to the ingestion pipeline.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import time
import math
import uuid
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.collection.database import insert_event

def calculate_shannon_entropy(filepath: str) -> float:
    try:
        if not os.path.isfile(filepath):
            return 0.0
        with open(filepath, 'rb') as f:
            data = f.read(65536) # Read first 64KB for rapid evaluation
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = {}
        for b in data:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        for count in byte_counts.values():
            p_x = count / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)
    except Exception:
        return 0.0

class CloudTelemetryHandler(FileSystemEventHandler):
    def __init__(self, event_callback=None):
        super().__init__()
        self.event_callback = event_callback or insert_event

    def emit_event(self, event_type: str, filepath: str):
        if os.path.basename(filepath).startswith('.'):
            return
        ext = os.path.splitext(filepath)[1]
        entropy = calculate_shannon_entropy(filepath) if event_type in ['create', 'modify', 'rename'] else 0.0
        size = os.path.getsize(filepath) if os.path.isfile(filepath) else 0
        
        event_dict = {
            'event_id': str(uuid.uuid4()),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'event_type': event_type,
            'file_path': filepath,
            'file_extension': ext,
            'entropy': entropy,
            'file_size': size,
            'process_name': 'collector_agent',
            'process_id': os.getpid(),
            'source_host': 'cloud-vm-01'
        }
        self.event_callback(event_dict)

    def on_created(self, event):
        if not event.is_directory:
            self.emit_event('create', event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.emit_event('modify', event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.emit_event('rename', event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.emit_event('delete', event.src_path)

def start_collector(watch_dir: str = 'data/sandbox/dummy_drive', run_duration: int = None):
    os.makedirs(watch_dir, exist_ok=True)
    handler = CloudTelemetryHandler()
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()
    print(f"[+] Telemetry collector active. Monitoring: {os.path.abspath(watch_dir)}")
    
    start_time = time.time()
    try:
        while True:
            time.sleep(1)
            if run_duration and (time.time() - start_time) > run_duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        print("[+] Telemetry collector gracefully terminated.")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'data/sandbox/dummy_drive'
    start_collector(target, run_duration=10)
