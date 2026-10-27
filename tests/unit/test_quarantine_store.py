"""
Unit Tests: Quarantine Store & Audit Persistence
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import os
import pytest
from src.quarantine.store import QuarantineStore

TEST_DB = "data/test_quarantine_unit.db"

@pytest.fixture(autouse=True)
def cleanup():
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass
    yield
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass

def test_quarantine_store_crud():
    qs = QuarantineStore(db_path=TEST_DB)
    
    # 1. Add record
    qs.add_record(
        sample_id="test_smpl_101",
        batch_id="batch_01",
        features={"f1": 12.5, "f2": 99.0},
        assigned_label=1,
        combined_score=0.88,
        detector_scores={"layer_a": 0.85, "layer_b": 0.90},
        reason="Layer B Label Inconsistency"
    )

    records = qs.get_records()
    assert len(records) == 1
    assert records[0]["sample_id"] == "test_smpl_101"
    assert records[0]["status"] == "PENDING_REVIEW"

    # 2. Update Status (Analyst triage)
    updated = qs.update_status("test_smpl_101", "CONFIRMED_POISON", "Confirmed flipped label via inspection")
    assert updated is True

    records_after = qs.get_records(status="CONFIRMED_POISON")
    assert len(records_after) == 1
    assert records_after[0]["reviewer_notes"] == "Confirmed flipped label via inspection"

    # 3. Stats
    stats = qs.get_summary_stats()
    assert stats["total_quarantined"] == 1
    assert stats["status_breakdown"]["CONFIRMED_POISON"] == 1
