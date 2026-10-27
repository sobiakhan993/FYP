"""
FastAPI REST API Service for Cloud IDS Poisoning Defense Platform
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Exposes endpoints for:
- Stream micro-batch ingestion & real-time multi-layer scoring
- Quarantine inspection, forensic triage, and audit status management
- Model registry active status query and instant rollback
- Experiment benchmark results retrieval
"""

import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import pandas as pd

from src.common.config import get_data_config
from src.common.logger import get_logger
from src.common.types import BatchRecord, BatchScoringResult, DecisionCategory
from src.detection.statistical import StatisticalAnomalyDetector
from src.detection.label_consistency import LabelConsistencyDetector
from src.detection.model_based import ModelBasedDetector
from src.detection.score_combiner import RiskScoreCombiner
from src.quarantine.store import QuarantineStore
from src.training.model_registry import ModelRegistry

logger = get_logger("FastAPIServer")

app = FastAPI(
    title="Cloud IDS Poisoning Defense API",
    description="Real-Time Detection & Mitigation of Data Poisoning Attacks on Continuously Retrained Cloud IDS",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State & Engines
cfg = get_data_config()
features = cfg["features"]["numerical"]
target = cfg["features"]["target"]

quarantine_store = QuarantineStore()
model_registry = ModelRegistry()
combiner = RiskScoreCombiner()

# Pre-fit detection layers on reference validation data
logger.info("Initializing multi-layer defense engines...")
val_df = pd.read_csv("data/processed/val.csv")
det_a = StatisticalAnomalyDetector().fit(val_df[features].values)
det_b = LabelConsistencyDetector(n_neighbors=11).fit(val_df[features].values, val_df[target].values)

active_model, active_meta = model_registry.get_active_model()
det_c = ModelBasedDetector(active_model)
logger.info(f"Defense engines initialized. Active model: {active_meta.get('version') if active_meta else 'None'}")

# Request/Response schemas
class ReviewRequest(BaseModel):
    new_status: str # "APPROVED_CLEAN", "CONFIRMED_POISON"
    reviewer_notes: Optional[str] = "Reviewed by operator"

class RollbackRequest(BaseModel):
    target_version: Optional[str] = None

@app.get("/health")
def health_check():
    active_m, meta = model_registry.get_active_model()
    return {
        "status": "healthy",
        "service": "cloud-ids-poisoning-defense",
        "active_model_version": meta["version"] if meta else "None",
        "quarantine_db_connected": True
    }

@app.post("/api/batches/ingest", response_model=BatchScoringResult)
def ingest_batch(batch: BatchRecord):
    t0 = time.perf_counter()
    n_samples = len(batch.samples)
    if n_samples == 0:
        raise HTTPException(status_code=400, detail="Batch contains no samples")

    # Extract vectors
    X = []
    y_claimed = []
    for s in batch.samples:
        vec = [s.features[f] for f in features]
        X.append(vec)
        y_claimed.append(s.label)

    import numpy as np
    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y_claimed, dtype=int)

    # Score across all 3 defense layers
    scores_a = det_a.score_samples(X_arr)
    scores_b = det_b.score_samples(X_arr, y_arr)
    scores_c = det_c.score_samples(X_arr, y_arr)

    combined_decisions = combiner.combine(scores_a, scores_b, scores_c)
    latency_ms = (time.perf_counter() - t0) * 1000

    quarantined_records = []
    sample_decisions = []
    accepted_count = 0
    quarantined_count = 0

    for i, dec in enumerate(combined_decisions):
        s = batch.samples[i]
        dec_info = {
            "sample_id": s.sample_id,
            "decision": dec["decision"],
            "combined_score": dec["combined_score"],
            "layer_scores": dec["layer_scores"],
            "reason": dec["reason"]
        }
        sample_decisions.append(dec_info)

        if dec["decision"] == DecisionCategory.QUARANTINED.value:
            quarantined_count += 1
            quarantined_records.append({
                "sample_id": s.sample_id,
                "batch_id": batch.batch_id,
                "features": s.features,
                "assigned_label": s.label,
                "combined_score": dec["combined_score"],
                "detector_scores": dec["layer_scores"],
                "reason": dec["reason"]
            })
        else:
            accepted_count += 1

    if quarantined_records:
        quarantine_store.add_batch_records(quarantined_records)

    logger.info(
        f"Batch {batch.batch_id} processed in {latency_ms:.2f}ms: Accepted={accepted_count}, Quarantined={quarantined_count}"
    )

    return BatchScoringResult(
        batch_id=batch.batch_id,
        total_samples=n_samples,
        accepted_count=accepted_count,
        quarantined_count=quarantined_count,
        sample_decisions=sample_decisions,
        processing_latency_ms=round(latency_ms, 2)
    )

class StreamReplayRequest(BaseModel):
    batch_size: int = 25
    poison_rate: float = 0.0

stream_cursor = 0

@app.post("/api/stream/replay-batch", response_model=BatchScoringResult)
def replay_stream_batch(req: StreamReplayRequest):
    global stream_cursor
    import uuid
    from datetime import datetime, timezone
    from src.attacks.label_flip import LabelFlipAttacker
    from src.common.types import SampleRecord

    total_val = len(val_df)
    start_i = stream_cursor % total_val
    end_i = min(start_i + req.batch_size, total_val)
    chunk = val_df.iloc[start_i:end_i].copy()
    stream_cursor += req.batch_size

    # Apply controlled attack if requested
    if req.poison_rate > 0:
        attacker = LabelFlipAttacker(random_seed=int(time.time()))
        chunk, _ = attacker.apply_attack(chunk, poison_rate=req.poison_rate)
        batch_id = f"attack_batch_{uuid.uuid4().hex[:8]}"
        src_name = f"adversarial_injector_{int(req.poison_rate*100)}pct"
    else:
        batch_id = f"stream_batch_{uuid.uuid4().hex[:8]}"
        src_name = "cloud_telemetry_replayer"

    samples = []
    now_str = datetime.now(timezone.utc).isoformat()
    for _, row in chunk.iterrows():
        feat_dict = {f: float(row[f]) for f in features}
        smpl = SampleRecord(
            sample_id=f"smpl_{uuid.uuid4().hex[:10]}",
            timestamp=now_str,
            features=feat_dict,
            label=int(row[target]),
            source_id=src_name,
            ground_truth_poisoned=bool(row.get("is_poisoned", False))
        )
        samples.append(smpl)

    batch_record = BatchRecord(
        batch_id=batch_id,
        source=src_name,
        received_at=now_str,
        record_count=len(samples),
        samples=samples
    )

    return ingest_batch(batch_record)


@app.get("/api/quarantine")
def list_quarantine_records(
    status: Optional[str] = Query(None, description="Filter by status: PENDING_REVIEW, APPROVED_CLEAN, CONFIRMED_POISON"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    records = quarantine_store.get_records(status=status, limit=limit, offset=offset)
    stats = quarantine_store.get_summary_stats()
    return {
        "summary": stats,
        "count": len(records),
        "records": records
    }

@app.patch("/api/quarantine/{sample_id}/review")
def review_quarantine_record(sample_id: str, req: ReviewRequest):
    success = quarantine_store.update_status(sample_id, req.new_status, req.reviewer_notes)
    if not success:
        raise HTTPException(status_code=404, detail="Quarantine record not found")
    return {"sample_id": sample_id, "updated_status": req.new_status, "notes": req.reviewer_notes}

@app.get("/api/quarantine/stats")
def quarantine_stats():
    return quarantine_store.get_summary_stats()

@app.get("/api/models/active")
def get_active_model_info():
    model, meta = model_registry.get_active_model()
    if not meta:
        raise HTTPException(status_code=404, detail="No active model in registry")
    return {
        "active_model": meta,
        "registry_manifest": model_registry.get_registry_manifest()
    }

@app.post("/api/models/rollback")
def rollback_model(req: RollbackRequest = Body(...)):
    success, msg = model_registry.rollback(req.target_version)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    
    # Reload active model into Layer C
    new_model, new_meta = model_registry.get_active_model()
    det_c.set_active_model(new_model)
    return {"success": True, "message": msg, "active_version": new_meta.get("version")}

@app.get("/api/experiments/results")
def get_experiments():
    res_path = "experiments/results/experiment_results.csv"
    import os
    if not os.path.exists(res_path):
        raise HTTPException(status_code=404, detail="No experiment results generated yet")
    df = pd.read_csv(res_path)
    return {
        "count": len(df),
        "results": df.to_dict(orient="records")
    }

# ================= INDUSTRY 5.0 AGENT ENDPOINTS =================
from src.agents.triage_agent import SecOpsTriageAgent
from src.agents.guard_agent import PoisoningGuardAgent

triage_agent = SecOpsTriageAgent(quarantine_store=quarantine_store)
guard_agent = PoisoningGuardAgent(registry=model_registry, quarantine_store=quarantine_store)

@app.get("/api/agents/triage/pending")
def agent_triage_pending(limit: int = Query(10, ge=1, le=50)):
    reports = triage_agent.triage_pending_quarantine(limit=limit)
    return {
        "agent": "SecOps Triage Agent",
        "triaged_count": len(reports),
        "reports": reports
    }

@app.get("/api/agents/triage/{sample_id}")
def agent_investigate_sample(sample_id: str):
    try:
        report = triage_agent.investigate_sample(sample_id)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

class PrepareTicketRequest(BaseModel):
    model_type: str = "random_forest"
    training_data_path: str = "data/processed/train.csv"

@app.post("/api/agents/guard/prepare-ticket")
def agent_prepare_ticket(req: PrepareTicketRequest = Body(...)):
    ticket = guard_agent.prepare_retraining_ticket(
        training_data_path=req.training_data_path,
        model_type=req.model_type
    )
    safe_ticket = {k: v for k, v in ticket.items() if k != "candidate_model_obj"}
    return safe_ticket

@app.get("/api/agents/guard/tickets")
def agent_list_tickets():
    return {
        "agent": "Poisoning Guard Agent",
        "tickets": guard_agent.get_pending_tickets()
    }

class ApproveTicketRequest(BaseModel):
    analyst_id: str = "Sir_Arfan_Naich"

@app.post("/api/agents/guard/tickets/{ticket_id}/approve")
def agent_approve_ticket(ticket_id: str, req: ApproveTicketRequest = Body(...)):
    try:
        updated_ticket = guard_agent.approve_and_deploy_ticket(ticket_id, analyst_id=req.analyst_id)
        # Refresh active model in Layer C
        new_model, new_meta = model_registry.get_active_model()
        det_c.set_active_model(new_model)
        return {
            "success": True,
            "message": f"Candidate model {updated_ticket['candidate_version']} approved by {req.analyst_id} and deployed to Cloud Production.",
            "ticket": {k: v for k, v in updated_ticket.items() if k != "candidate_model_obj"}
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# Mount Web Dashboard Frontend
import os
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(dashboard_path):
    app.mount("/", StaticFiles(directory=dashboard_path, html=True), name="dashboard")

