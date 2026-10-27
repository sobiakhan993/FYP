"""
Data schemas and entity models for Cloud IDS Poisoning Defense.
Complies with Section 5.3 (Suggested data entities) of the FYDP specification.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class DecisionCategory(str, Enum):
    ACCEPTED = "ACCEPTED"
    QUARANTINED = "QUARANTINED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"

class DetectorScore(BaseModel):
    detector_name: str
    score: float
    threshold: float
    is_anomaly: bool
    details: Optional[Dict[str, Any]] = None

class SampleRecord(BaseModel):
    sample_id: str
    timestamp: str
    features: Dict[str, float]
    label: int # 0: Benign, 1: Attack
    source_id: Optional[str] = "cloud_telemetry_flow"
    ground_truth_poisoned: Optional[bool] = None # For evaluation metrics ONLY, not defense input

class BatchRecord(BaseModel):
    batch_id: str
    source: str
    received_at: str
    record_count: int
    samples: List[SampleRecord]

class BatchScoringResult(BaseModel):
    batch_id: str
    total_samples: int
    accepted_count: int
    quarantined_count: int
    sample_decisions: List[Dict[str, Any]]
    processing_latency_ms: float

class QuarantineRecord(BaseModel):
    sample_id: str
    batch_id: str
    features: Dict[str, float]
    assigned_label: int
    combined_risk_score: float
    detector_scores: Dict[str, float]
    reason: str
    quarantined_at: str
    status: str = "PENDING_REVIEW" # PENDING_REVIEW, APPROVED_CLEAN, CONFIRMED_POISON

class ModelValidationResult(BaseModel):
    model_id: str
    version: str
    dataset_version: str
    evaluated_at: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    passed: bool
    block_reason: Optional[str] = None
