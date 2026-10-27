"""
Integration Tests: FastAPI REST Endpoints & Real-Time Ingestion
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import pytest
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["active_model_version"] != "None"

def test_batch_ingestion_and_scoring():
    payload = {
        "batch_id": "integration_test_batch_001",
        "source": "unit_test_emitter",
        "received_at": "2026-10-27T12:00:00Z",
        "record_count": 2,
        "samples": [
            {
                "sample_id": "test_smpl_clean_01",
                "timestamp": "2026-10-27T12:00:00Z",
                "features": {
                    "flow_duration": 15.0,
                    "total_fwd_packets": 12.0,
                    "total_bwd_packets": 15.0,
                    "total_length_fwd_packets": 3000.0,
                    "total_length_bwd_packets": 9750.0,
                    "flow_bytes_per_sec": 850.0,
                    "flow_packets_per_sec": 1.8,
                    "fwd_packet_length_mean": 250.0,
                    "bwd_packet_length_mean": 650.0,
                    "flow_iat_mean": 0.55,
                    "fwd_iat_mean": 1.25,
                    "packet_length_std": 120.0,
                    "syn_flag_count": 0.0,
                    "ack_flag_count": 1.0,
                    "down_up_ratio": 1.25,
                    "average_packet_size": 472.0
                },
                "label": 0
            },
            {
                "sample_id": "test_smpl_poison_02",
                "timestamp": "2026-10-27T12:00:00Z",
                "features": {
                    "flow_duration": 0.05,
                    "total_fwd_packets": 250.0,
                    "total_bwd_packets": 1.0,
                    "total_length_fwd_packets": 15000.0,
                    "total_length_bwd_packets": 40.0,
                    "flow_bytes_per_sec": 300800.0,
                    "flow_packets_per_sec": 5020.0,
                    "fwd_packet_length_mean": 60.0,
                    "bwd_packet_length_mean": 40.0,
                    "flow_iat_mean": 0.0002,
                    "fwd_iat_mean": 0.0002,
                    "packet_length_std": 10.0,
                    "syn_flag_count": 1.0,
                    "ack_flag_count": 0.0,
                    "down_up_ratio": 0.004,
                    "average_packet_size": 59.9
                },
                "label": 0 # Flooding traffic claiming to be Benign -> Label Flipped!
            }
        ]
    }

    res = client.post("/api/batches/ingest", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["batch_id"] == "integration_test_batch_001"
    assert data["total_samples"] == 2
    assert "processing_latency_ms" in data

def test_quarantine_endpoints():
    res = client.get("/api/quarantine?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "records" in data

def test_experiments_results_endpoint():
    res = client.get("/api/experiments/results")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] > 0
    assert len(data["results"]) > 0
