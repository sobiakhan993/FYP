"""
Agent 1: SecOps Triage Agent
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
Industry 5.0 Human-Centric & Explainable Cybersecurity Component

Role:
- Automatically investigates suspicious samples routed to the Quarantine Store.
- Synthesizes multi-layer detection signals (Isolation Forest, k-NN consistency, Loss margin).
- Generates structured, explainable forensic incident briefings for SecOps analysts.
- Recommends decisive action (CONFIRM_POISON vs APPROVE_CLEAN) with confidence scores.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from src.common.logger import get_logger
from src.quarantine.store import QuarantineStore
from src.detection.explainability import FlowExplainabilityEngine

logger = get_logger("SecOpsTriageAgent")

class SecOpsTriageAgent:
    def __init__(self, quarantine_store: Optional[QuarantineStore] = None):
        self.store = quarantine_store or QuarantineStore()
        self.explainer = FlowExplainabilityEngine()
        logger.info("SecOps Triage Agent online & connected to Quarantine Store.")

    def investigate_sample(self, sample_id: str) -> Dict[str, Any]:
        """
        Conducts deep forensic triage on a quarantined sample.
        """
        records = [r for r in self.store.get_records(limit=500) if r["sample_id"] == sample_id]
        if not records:
            raise ValueError(f"Quarantined sample {sample_id} not found in store.")

        record = records[0]
        features = record["features"]
        claimed_label = record["assigned_label"]
        layer_scores = record["detector_scores"]
        combined_score = record["combined_score"]

        # Run explainability attribution
        explanation = self.explainer.explain_record(
            features=features,
            claimed_label=claimed_label,
            layer_scores=layer_scores,
            combined_score=combined_score
        )

        # Formulate triage recommendation
        rec_action, severity, confidence, rationale = self._formulate_recommendation(
            explanation, combined_score, layer_scores
        )

        now_str = datetime.now(timezone.utc).isoformat()
        report = {
            "sample_id": sample_id,
            "investigated_at": now_str,
            "severity": severity,
            "confidence_score": round(confidence, 4),
            "threat_classification": explanation["threat_type"],
            "executive_summary": explanation["threat_diagnosis"],
            "recommended_action": rec_action,
            "mitigation_rationale": rationale,
            "top_anomalous_features": explanation["top_attributions"],
            "multi_layer_breakdown": layer_scores,
            "current_quarantine_status": record["status"]
        }

        logger.info(f"Triage completed for {sample_id}: Severity={severity}, Action={rec_action}")
        return report

    def _formulate_recommendation(
        self,
        explanation: Dict[str, Any],
        combined_score: float,
        layer_scores: Dict[str, float]
    ) -> (str, str, float, str):
        knn_score = layer_scores.get("layer_b_label_consistency", 0.0)
        margin_score = layer_scores.get("layer_c_model_based", 0.0)
        iso_score = layer_scores.get("layer_a_statistical", 0.0)

        # High confidence label-flipping poison
        if knn_score >= 0.70 and margin_score >= 0.60:
            severity = "CRITICAL"
            confidence = 0.98
            action = "CONFIRM_POISON"
            rationale = (
                f"Definitive label-flipping signature: Sample claims opposite class despite 90%+ neighborhood "
                f"belonging to opposing manifold (k-NN score: {knn_score:.2f}, Margin loss: {margin_score:.2f}). "
                f"Permanent exclusion from training buffer is strongly recommended."
            )
        elif combined_score >= 0.65:
            severity = "HIGH"
            confidence = 0.90
            action = "CONFIRM_POISON"
            rationale = (
                f"Composite risk ({combined_score:.2f}) indicates severe data corruption or crafted sample injection. "
                f"Exclude from retraining to prevent class boundary distortion."
            )
        elif combined_score >= 0.40 and iso_score >= 0.55 and knn_score < 0.30:
            severity = "MEDIUM"
            confidence = 0.75
            action = "APPROVE_CLEAN"
            rationale = (
                f"Statistical novelty without label contradiction (k-NN score: {knn_score:.2f}). "
                f"Likely legitimate cloud workload drift or new valid feature pattern. Recommend manual analyst verification."
            )
        else:
            severity = "LOW"
            confidence = 0.70
            action = "APPROVE_CLEAN"
            rationale = "Marginal risk score. Likely benign border point."

        return action, severity, confidence, rationale

    def triage_pending_quarantine(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Triages all pending records in the quarantine store.
        """
        pending = self.store.get_records(status="PENDING_REVIEW", limit=limit)
        reports = []
        for p in pending:
            rep = self.investigate_sample(p["sample_id"])
            reports.append(rep)
        return reports

if __name__ == "__main__":
    agent = SecOpsTriageAgent()
    pending = agent.store.get_records(limit=1)
    if pending:
        rep = agent.investigate_sample(pending[0]["sample_id"])
        print("Triage Report:\n", rep)
    else:
        print("No pending records to triage.")
