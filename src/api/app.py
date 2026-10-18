"""
Cloud Threat Detector REST API & Web Server
Serves real-time inference, alert triage, poisoning quarantine audit,
telemetry ingestion, and the interactive SecOps Web Dashboard.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import json
import time
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, send_file, send_from_directory, Response

from src.collection.database import (
    get_db_connection, insert_event, insert_feature_row, insert_alert, init_db
)
from src.detection.detector_engine import ThreatDetectorEngine
from src.poisoning.poison_sanitizer import PoisoningSanitizer
from src.monitoring.sandbox_simulator import (
    run_ransomware_simulation, run_benign_simulation, setup_dummy_environment
)
from src.collection.event_consumer import EventConsumer

# Initialize Flask App
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'dashboard'))
app = Flask(__name__, static_folder=STATIC_DIR)

# Global instances
detector_engine = ThreatDetectorEngine(load_models=True)
event_consumer = EventConsumer()
poisoning_sanitizer = PoisoningSanitizer()

# Ensure DB is created
init_db()

# ----------------- WEB DASHBOARD ROUTES -----------------

@app.route('/')
def index():
    return send_from_directory(STATIC_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(STATIC_DIR, filename)

# ----------------- AUTHENTICATION -----------------

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and user['password_hash'] == password:
        token = f"TOKEN-{uuid.uuid4().hex[:16]}"
        return jsonify({
            'status': 'success',
            'token': token,
            'role': user['role'],
            'username': user['username']
        })
    return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401

# ----------------- SYSTEM STATUS & TELEMETRY -----------------

@app.route('/api/system/status', methods=['GET'])
def system_status():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM events;")
    total_events = cursor.fetchone()['cnt']
    cursor.execute("SELECT COUNT(*) as cnt FROM alerts WHERE status = 'active';")
    active_alerts = cursor.fetchone()['cnt']
    cursor.execute("SELECT COUNT(*) as cnt FROM quarantine_store;")
    quarantine_count = cursor.fetchone()['cnt']
    conn.close()
    
    sys_metrics = event_consumer.get_system_rates()
    
    return jsonify({
        'status': 'operational',
        'active_model': 'Production Random Forest v1.0 + Isolation Forest',
        'dual_engine_status': 'active',
        'total_events_processed': total_events,
        'active_alerts': active_alerts,
        'quarantined_samples': quarantine_count,
        'system_metrics': sys_metrics
    })

# ----------------- REAL-TIME INFERENCE & SCORING -----------------

@app.route('/api/inference/score', methods=['POST'])
def score_features():
    data = request.get_json() or {}
    result = detector_engine.score_feature_vector(data)
    
    # If alert is required, store in DB and trigger alert
    alert_id = None
    if result.get('alert_required'):
        alert_id = f"ALT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        alert_dict = {
            'alert_id': alert_id,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': result['severity'],
            'threat_type': result['verdict'],
            'confidence_score': result['composite_score'],
            'anomaly_score': result['anomaly_score'],
            'affected_resource': data.get('affected_resource', '/data/cloud/shared_volume/'),
            'status': 'active',
            'details_json': {
                'supervised_prob': result['supervised_probability'],
                'top_signals': result['top_signals']
            }
        }
        insert_alert(alert_dict)
        result['alert_id'] = alert_id
        
    return jsonify(result)

# ----------------- ALERTS MANAGEMENT -----------------

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    severity = request.args.get('severity')
    status = request.args.get('status')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT 50;"
    
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({'alerts': rows, 'total': len(rows)})

@app.route('/api/alerts/<alert_id>/status', methods=['POST'])
def update_alert_status(alert_id):
    data = request.get_json() or {}
    new_status = data.get('status', 'acknowledged')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'updated', 'alert_id': alert_id, 'new_status': new_status})

# ----------------- ATTACK LOGS & RECENT FEATURES -----------------

@app.route('/api/attacks/log', methods=['GET'])
def get_attack_log():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attack_log ORDER BY id DESC LIMIT 50;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({'attacks': rows})

@app.route('/api/features/recent', methods=['GET'])
def get_recent_features():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM features ORDER BY id DESC LIMIT 30;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({'features': list(reversed(rows))})

# ----------------- POISONING DEFENSE & QUARANTINE -----------------

@app.route('/api/poisoning/quarantine', methods=['GET'])
def get_quarantine():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantine_store ORDER BY id DESC LIMIT 100;")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({'quarantined_samples': rows, 'total': len(rows)})

@app.route('/api/poisoning/trigger-defense', methods=['POST'])
def trigger_poisoning_defense():
    data = request.get_json() or {}
    dataset_name = data.get('dataset', 'train_poisoned_label_flip_10pct.csv')
    dataset_path = os.path.join('data/poisoned', dataset_name)
    
    if not os.path.exists(dataset_path):
        return jsonify({'error': 'Dataset not found'}), 404
        
    clean_df, report = poisoning_sanitizer.inspect_and_sanitize(dataset_path)
    gate = poisoning_sanitizer.validate_and_gate_retraining(clean_df)
    
    return jsonify({
        'status': 'completed',
        'report': report,
        'validation_gate': gate
    })

# ----------------- LIVE SANDBOX SIMULATOR TRIGGERS -----------------

@app.route('/api/sandbox/simulate-attack', methods=['POST'])
def trigger_attack_sim():
    """Triggers safe sandbox ransomware encryption and feeds events into the live pipeline."""
    try:
        events = run_ransomware_simulation(target_count=12, delay_between_files=0.02)
        feat = event_consumer.aggregate_window_features(events, window_duration=5.0)
        row_id = insert_feature_row(feat)
        
        # Immediate scoring
        score_res = detector_engine.score_feature_vector(feat)
        if score_res.get('alert_required'):
            alert_id = f"ALT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            insert_alert({
                'alert_id': alert_id,
                'timestamp': datetime.utcnow().isoformat(),
                'severity': score_res['severity'],
                'threat_type': score_res['verdict'],
                'confidence_score': score_res['composite_score'],
                'anomaly_score': score_res['anomaly_score'],
                'affected_resource': 'data/sandbox/dummy_drive/',
                'status': 'active',
                'feature_id': row_id,
                'details_json': score_res
            })
            score_res['alert_id'] = alert_id
            
        return jsonify({
            'status': 'attack_simulated',
            'encrypted_files_count': len(events),
            'computed_feature_row': feat,
            'detection_result': score_res
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/sandbox/simulate-benign', methods=['POST'])
def trigger_benign_sim():
    try:
        events = run_benign_simulation(duration_seconds=3)
        feat = event_consumer.aggregate_window_features(events, window_duration=5.0)
        row_id = insert_feature_row(feat)
        score_res = detector_engine.score_feature_vector(feat)
        return jsonify({
            'status': 'benign_simulated',
            'events_count': len(events),
            'computed_feature_row': feat,
            'detection_result': score_res
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ----------------- FORENSIC REPORT EXPORT -----------------

@app.route('/api/reports/export', methods=['GET'])
def export_report():
    export_format = request.args.get('format', 'csv')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attack_log ORDER BY id DESC;")
    attacks = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    if export_format == 'csv':
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Attack ID', 'Detected At', 'Attack Type', 'Severity', 'Confidence', 'Affected Resource', 'Status'])
        for a in attacks:
            writer.writerow([
                a.get('attack_id'), a.get('detected_at'), a.get('attack_type'),
                a.get('severity'), a.get('confidence'), a.get('affected_resource'),
                a.get('mitigation_status')
            ])
        csv_data = output.getvalue()
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=security_incident_report.csv"}
        )
    return jsonify({'attacks': attacks})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[+] Starting Cloud Threat Detector API on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=False)
