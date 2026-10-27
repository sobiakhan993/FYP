"""
Agent 2: Poisoning Guard Agent
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
Industry 5.0 Human-in-the-Loop Safe Retraining & Model Governance Orchestrator

Role:
- Protects the retraining pipeline against adversarial corruption and poisoned candidate promotion.
- Enforces strict zero-quarantine training buffer hygiene.
- Coordinates evaluation against the immutable Trusted Holdout Gate.
- Generates Human-in-the-Loop Model Promotion Tickets requiring analyst sign-off before cloud deployment.
- Orchestrates automated or emergency rollbacks.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
from src.common.logger import get_logger
from src.common.config import get_data_config
from src.training.train_candidate import CandidateTrainer
from src.training.validate_candidate import TrustedValidationGate
from src.training.model_registry import ModelRegistry
from src.quarantine.store import QuarantineStore

logger = get_logger("PoisoningGuardAgent")

class PoisoningGuardAgent:
    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        gate: Optional[TrustedValidationGate] = None,
        quarantine_store: Optional[QuarantineStore] = None
    ):
        self.registry = registry or ModelRegistry()
        self.gate = gate or TrustedValidationGate()
        self.quarantine_store = quarantine_store or QuarantineStore()
        self.pending_tickets: Dict[str, Dict[str, Any]] = {}
        logger.info("Poisoning Guard Agent initialized and active.")

    def inspect_training_buffer(self, buffer_df: pd.DataFrame) -> Tuple[bool, str]:
        """
        Validates that the incoming retraining buffer contains no quarantined or corrupted records.
        """
        if len(buffer_df) < 50:
            return False, f"Buffer underflow: {len(buffer_df)} records is below minimum retraining threshold (50 records)."

        # Check if any sample matches quarantined IDs
        quarantined_ids = set([r["sample_id"] for r in self.quarantine_store.get_records(limit=10000)])
        if "sample_id" in buffer_df.columns:
            overlap = quarantined_ids.intersection(set(buffer_df["sample_id"]))
            if overlap:
                return False, f"Sanitization policy violation: {len(overlap)} quarantined records detected in training buffer!"

        return True, "Buffer verified clean and compliant with zero-quarantine policy."

    def prepare_retraining_ticket(
        self,
        training_data_path: str = "data/processed/train.csv",
        model_type: str = "random_forest"
    ) -> Dict[str, Any]:
        """
        Trains a candidate model, validates it on the trusted holdout gate,
        and prepares a formal Model Promotion Ticket for analyst review.
        """
        now_str = datetime.now(timezone.utc).isoformat()
        ticket_id = f"tkt_retrain_{uuid.uuid4().hex[:8]}"

        df_train = pd.read_csv(training_data_path)
        is_clean, msg = self.inspect_training_buffer(df_train)
        if not is_clean:
            return {
                "ticket_id": ticket_id,
                "created_at": now_str,
                "status": "REJECTED_BUFFER_POLLUTED",
                "reason": msg,
                "candidate_version": None,
                "metrics": None
            }

        # Train candidate model
        trainer = CandidateTrainer(model_type=model_type)
        candidate_model = trainer.train(training_data_path)

        # Retrieve active model metrics for regression gating
        active_model, active_meta = self.registry.get_active_model()
        active_metrics = active_meta["validation_metrics"] if active_meta else None
        active_ver = active_meta.get("version", "None") if active_meta else "None"

        # Gate check on isolated holdout
        passed, val_res = self.gate.evaluate_and_gate(
            candidate_model, candidate_id=ticket_id, active_baseline_metrics=active_metrics
        )

        # Propose candidate version
        if not active_meta or not active_meta.get("version"):
            cand_ver = "v1.0.0"
        else:
            parts = active_meta["version"].lstrip("v").split(".")
            cand_ver = f"v{parts[0]}.{int(parts[1]) + 1}.0"

        metrics = {
            "accuracy": val_res.accuracy,
            "precision": val_res.precision,
            "recall": val_res.recall,
            "f1_score": val_res.f1_score,
            "false_positive_rate": val_res.false_positive_rate
        }

        if passed:
            status = "AWAITING_ANALYST_APPROVAL"
            recommendation = (
                f"Candidate model {cand_ver} PASSED all Trusted Validation Gate checks with F1={val_res.f1_score:.4f}. "
                f"Zero regression detected relative to active {active_ver}. Recommended for production promotion."
            )
        else:
            status = "BLOCKED_BY_GATE"
            recommendation = (
                f"Candidate model {cand_ver} BLOCKED by Trusted Validation Gate: {val_res.block_reason}. "
                f"Promotion halted to protect cloud IDS integrity."
            )

        ticket = {
            "ticket_id": ticket_id,
            "created_at": now_str,
            "status": status,
            "candidate_version": cand_ver,
            "active_version": active_ver,
            "model_type": model_type,
            "metrics": metrics,
            "gate_passed": passed,
            "block_reason": val_res.block_reason,
            "recommendation": recommendation,
            "candidate_model_obj": candidate_model if passed else None
        }

        self.pending_tickets[ticket_id] = ticket
        logger.info(f"Retraining ticket generated: {ticket_id} ({status})")
        return ticket

    def approve_and_deploy_ticket(self, ticket_id: str, analyst_id: str = "SOC_Supervisor") -> Dict[str, Any]:
        """
        Industry 5.0 Human-in-the-Loop Sign-off:
        Promotes the approved candidate model only after explicit analyst authorization.
        """
        if ticket_id not in self.pending_tickets:
            raise ValueError(f"Retraining ticket {ticket_id} not found.")

        ticket = self.pending_tickets[ticket_id]
        if ticket["status"] != "AWAITING_ANALYST_APPROVAL":
            raise ValueError(f"Ticket {ticket_id} cannot be approved in status: {ticket['status']}")

        model_obj = ticket["candidate_model_obj"]
        version_tag = ticket["candidate_version"]
        metrics = ticket["metrics"]

        # Promote in registry
        promoted_ver = self.registry.register_and_promote(
            model=model_obj,
            metrics=metrics,
            version_tag=version_tag,
            notes=f"Authorized and approved by {analyst_id} via Industry 5.0 HITL Protocol"
        )

        ticket["status"] = "DEPLOYED_TO_PRODUCTION"
        ticket["approved_by"] = analyst_id
        ticket["deployed_at"] = datetime.now(timezone.utc).isoformat()
        ticket["candidate_model_obj"] = None # Free memory

        logger.info(f"Ticket {ticket_id} approved by {analyst_id}. Active model is now {promoted_ver}.")
        return ticket

    def get_pending_tickets(self) -> List[Dict[str, Any]]:
        # Return ticket dicts without the model object
        safe_list = []
        for t in self.pending_tickets.values():
            copy_t = {k: v for k, v in t.items() if k != "candidate_model_obj"}
            safe_list.append(copy_t)
        return safe_list

if __name__ == "__main__":
    guard = PoisoningGuardAgent()
    tkt = guard.prepare_retraining_ticket("data/processed/train.csv")
    print("Generated Ticket:\n", tkt["ticket_id"], tkt["status"], tkt["recommendation"])
    if tkt["status"] == "AWAITING_ANALYST_APPROVAL":
        res = guard.approve_and_deploy_ticket(tkt["ticket_id"], analyst_id="Sir_Arfan_Naich")
        print("Promoted successfully:", res["candidate_version"])
