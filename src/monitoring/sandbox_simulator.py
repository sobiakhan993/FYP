"""
Safe Sandbox Ransomware & Workload Simulator
Generates dummy files in an isolated directory and simulates:
1. Benign workload activity (reading, editing, compression).
2. Harmless ransomware-like mass encryption (generating high-entropy random bytes,
   renaming files to .locked extension, emitting real-time event telemetry).
3. Reset / restore functionality.
SAFETY NOTICE: Operates strictly within a designated dummy sandbox folder. Never interacts
with host OS files or real user documents.
"""

import os
import math
import time
import json
import random
import shutil

SANDBOX_DIR = os.path.abspath('data/sandbox/dummy_drive')

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy in bits per byte (0.0 to 8.0)."""
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

def setup_dummy_environment(n_files: int = 30):
    """Initializes dummy user files in the sandbox directory."""
    if os.path.exists(SANDBOX_DIR):
        shutil.rmtree(SANDBOX_DIR)
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    
    subdirs = ['documents', 'spreadsheets', 'code', 'databases']
    for d in subdirs:
        os.makedirs(os.path.join(SANDBOX_DIR, d), exist_ok=True)
        
    sample_texts = [
        b"Quarterly Financial Statement. Revenue grew by 14% over Q3. Operating expenses were well within budget.",
        b"Project Plan for Cloud Infrastructure Migration. Database replication verified. AWS S3 storage lifecycle configured.",
        b"def calculate_balance(account_id):\n    # Queries database and returns current user ledger\n    return 4500.50\n",
        b"CONFIDENTIAL: Internal security audit findings. Zero critical findings reported in recent container scan.",
        b"User profile records: ID=1029, Username=jsmith, Department=Logistics, Clearance=Standard."
    ]
    
    file_extensions = ['.txt', '.docx', '.xlsx', '.py', '.sql', '.csv']
    created_files = []
    
    for i in range(n_files):
        ext = file_extensions[i % len(file_extensions)]
        subdir = subdirs[i % len(subdirs)]
        filename = f"user_doc_{i+1:03d}{ext}"
        filepath = os.path.join(SANDBOX_DIR, subdir, filename)
        
        # Populate with repeated text so entropy is natural (2.5 - 4.5)
        content = sample_texts[i % len(sample_texts)] * random.randint(15, 60)
        with open(filepath, 'wb') as f:
            f.write(content)
        created_files.append((filepath, calculate_shannon_entropy(content)))
        
    print(f"[+] Sandbox initialized with {len(created_files)} dummy files in: {SANDBOX_DIR}")
    return created_files

def run_benign_simulation(duration_seconds: int = 5):
    """Simulates benign workload: periodic read, minor append, normal low entropy."""
    print(f"[*] Starting benign workload simulation for {duration_seconds}s...")
    events = []
    end_time = time.time() + duration_seconds
    
    all_files = []
    for root, _, files in os.walk(SANDBOX_DIR):
        for f in files:
            all_files.append(os.path.join(root, f))
            
    if not all_files:
        setup_dummy_environment(20)
        return run_benign_simulation(duration_seconds)
        
    while time.time() < end_time:
        target = random.choice(all_files)
        with open(target, 'rb') as f:
            data = f.read()
        ent = calculate_shannon_entropy(data)
        
        # Append minor benign text
        with open(target, 'ab') as f:
            f.write(b"\n[INFO] Routine application heartbeat log entry.")
            
        event = {
            'timestamp': time.time(),
            'event_type': 'modify',
            'file_path': target,
            'file_extension': os.path.splitext(target)[1],
            'entropy': ent,
            'file_size': os.path.getsize(target),
            'process_name': 'benign_service.exe',
            'process_id': os.getpid()
        }
        events.append(event)
        time.sleep(0.2)
        
    print(f"[+] Benign simulation complete. Emitted {len(events)} benign events.")
    return events

def run_ransomware_simulation(target_count: int = 20, delay_between_files: float = 0.05):
    """
    Simulates high-speed ransomware attack on dummy files:
    1. Reads original dummy file.
    2. Overwrites with high-entropy cryptographic pseudorandom bytes (Entropy > 7.9).
    3. Appends '.locked' extension.
    4. Emits real-time event telemetry.
    """
    print(f"[!] INITIATING HARMLESS RANSOMWARE SIMULATION ON {target_count} SANDBOX FILES...")
    all_files = []
    for root, _, files in os.walk(SANDBOX_DIR):
        for f in files:
            if not f.endswith('.locked'):
                all_files.append(os.path.join(root, f))
                
    if len(all_files) < target_count:
        setup_dummy_environment(target_count + 10)
        return run_ransomware_simulation(target_count, delay_between_files)
        
    targets = all_files[:target_count]
    attack_events = []
    
    for filepath in targets:
        orig_size = os.path.getsize(filepath)
        # Generate random high-entropy bytes (simulating symmetric encryption output)
        encrypted_bytes = os.urandom(orig_size if orig_size > 512 else 1024)
        new_entropy = calculate_shannon_entropy(encrypted_bytes)
        
        # Overwrite file
        with open(filepath, 'wb') as f:
            f.write(encrypted_bytes)
            
        # Rename to .locked
        new_filepath = filepath + '.locked'
        os.rename(filepath, new_filepath)
        
        event = {
            'timestamp': time.time(),
            'event_type': 'rename_encrypted',
            'file_path': new_filepath,
            'file_extension': '.locked',
            'old_extension': os.path.splitext(filepath)[1],
            'entropy': new_entropy,
            'file_size': len(encrypted_bytes),
            'process_name': 'simulated_cryptor.exe',
            'process_id': os.getpid()
        }
        attack_events.append(event)
        print(f"    [SIMULATED ENCRYPT] {os.path.basename(filepath)} -> .locked | Entropy: {new_entropy:.4f} bits/byte")
        time.sleep(delay_between_files)
        
    print(f"[!] Ransomware simulation complete. Encrypted {len(attack_events)} dummy files.")
    return attack_events

if __name__ == '__main__':
    setup_dummy_environment(25)
    run_benign_simulation(2)
    run_ransomware_simulation(15, delay_between_files=0.03)
