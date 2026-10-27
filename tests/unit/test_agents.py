"""
Unit Tests: Industry 5.0 Autonomous Agents & Explainability
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import pytest
from src.detection.explainability import FlowExplainabilityEngine
from src.agents.triage_agent import SecOpsTriageAgent
from src.agents.guard_agent import PoisoningGuardAgent
from src.quarantine.store import QuarantineStore

def test_explainability_attribution():
    explainer = FlowExplainabilityEngine()
    features = {f: 0.0 for f in explainer.features}
    features["flow_bytes_per_sec"] = 5.0 # High anomaly
    features["syn_flag_count"] = 1.0

    res = explainer.explain_record(
        features=features,
        claimed_label=0,
        layer_scores={"layer_a_statistical": 0.8, "layer_b_label_consistency": 0.9, "layer_c_model_based": 0.85},
        combined_score=0.85
    )

    assert "threat_diagnosis" in res
    assert "top_attributions" in res
    assert len(res["top_attributions"]) > 0
    assert res["threat_type"] == "LABEL_FLIPPING"

def test_triage_agent_investigation():
    store = QuarantineStore("data/test_quarantine_agents.db")
    features = {f: 0.1 for f in ["flow_duration", "total_fwd_packets", "total_bwd_packets",
                                 "total_length_fwd_packets", "total_length_bwd_packets", "flow_bytes_per_sec",
                                 "flow_packets_per_sec", "fwd_packet_length_mean", "bwd_packet_length_mean",
                                 "flow_iat_mean", "fwd_iat_mean", "packet_length_std", "syn_flag_count",
                                 "ack_flag_count", "down_up_ratio", "average_packet_size"]}
    
    store.add_record(
        sample_id="agent_test_smpl_01",
        batch_id="b1",
        features=features,
        assigned_label=0,
        combined_score=0.92,
        detector_scores={"layer_a_statistical": 0.85, "layer_b_label_consistency": 0.98, "layer_c_model_based": 0.90},
        reason="Test evasion"
    )

    agent = SecOpsTriageAgent(quarantine_store=store)
    report = agent.investigate_sample("agent_test_smpl_01")

    assert report["severity"] in ["CRITICAL", "HIGH"]
    assert report["recommended_action"] == "CONFIRM_POISON"
    assert "mitigation_rationale" in report

def test_poisoning_guard_agent_ticket_lifecycle():
    guard = PoisoningGuardAgent()
    ticket = guard.prepare_retraining_ticket("data/processed/train.csv")
    
    assert "ticket_id" in ticket
    assert ticket["status"] in ["AWAITING_ANALYST_APPROVAL", "BLOCKED_BY_GATE"]
    
    if ticket["status"] == "AWAITING_ANALYST_APPROVAL":
        approved = guard.approve_and_deploy_ticket(ticket["ticket_id"], analyst_id="Supervisor_Test")
        assert approved["status"] == "DEPLOYED_TO_PRODUCTION"
        assert approved["approved_by"] == "Supervisor_Test"
