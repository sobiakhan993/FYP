"""
Quarantine Store & Audit Telemetry Engine
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Complies with FR-05 & Section 5.1:
Persists quarantined records in an auditable SQLite store instead of silently dropping them.
Allows SecOps analysts and autonomous triage agents to inspect forensic features,
review multi-layer detection scores, and approve or confirm poison classifications.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import pandas as pd
from src.common.config import get_detectors_config
from src.common.logger import get_logger

logger = get_logger("QuarantineStore")

class QuarantineStore:
    def __init__(self, db_path: Optional[str] = None):
        cfg = get_detectors_config().get("quarantine", {})
        self.db_path = Path(db_path or cfg.get("db_path", "data/quarantine.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_records (
                    sample_id TEXT PRIMARY KEY,
                    batch_id TEXT,
                    features_json TEXT NOT NULL,
                    assigned_label INTEGER NOT NULL,
                    combined_score REAL NOT NULL,
                    detector_scores_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
                    reviewed_at TEXT,
                    reviewer_notes TEXT
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_records(status);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_quarantine_batch ON quarantine_records(batch_id);
            """)
            conn.commit()

    def add_record(
        self,
        sample_id: str,
        batch_id: str,
        features: Dict[str, float],
        assigned_label: int,
        combined_score: float,
        detector_scores: Dict[str, float],
        reason: str
    ) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO quarantine_records
                (sample_id, batch_id, features_json, assigned_label, combined_score,
                 detector_scores_json, reason, quarantined_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_REVIEW')
            """, (
                sample_id,
                batch_id,
                json.dumps(features),
                int(assigned_label),
                float(combined_score),
                json.dumps(detector_scores),
                reason,
                now_str
            ))
            conn.commit()

    def add_batch_records(self, records: List[Dict[str, Any]]) -> int:
        now_str = datetime.now(timezone.utc).isoformat()
        inserted = 0
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for r in records:
                cursor.execute("""
                    INSERT OR REPLACE INTO quarantine_records
                    (sample_id, batch_id, features_json, assigned_label, combined_score,
                     detector_scores_json, reason, quarantined_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_REVIEW')
                """, (
                    r["sample_id"],
                    r.get("batch_id", "manual_ingest"),
                    json.dumps(r["features"]),
                    int(r["assigned_label"]),
                    float(r["combined_score"]),
                    json.dumps(r.get("detector_scores", {})),
                    r.get("reason", "Multi-layer threshold exceeded"),
                    now_str
                ))
                inserted += 1
            conn.commit()
        logger.info(f"Persisted {inserted} records into Quarantine Store.")
        return inserted

    def get_records(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("""
                    SELECT * FROM quarantine_records
                    WHERE status = ?
                    ORDER BY quarantined_at DESC
                    LIMIT ? OFFSET ?
                """, (status, limit, offset))
            else:
                cursor.execute("""
                    SELECT * FROM quarantine_records
                    ORDER BY quarantined_at DESC
                    LIMIT ? OFFSET ?
                """, (limit, offset))
            
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "sample_id": r["sample_id"],
                    "batch_id": r["batch_id"],
                    "features": json.loads(r["features_json"]),
                    "assigned_label": r["assigned_label"],
                    "combined_score": r["combined_score"],
                    "detector_scores": json.loads(r["detector_scores_json"]),
                    "reason": r["reason"],
                    "quarantined_at": r["quarantined_at"],
                    "status": r["status"],
                    "reviewed_at": r["reviewed_at"],
                    "reviewer_notes": r["reviewer_notes"]
                })
            return results

    def update_status(self, sample_id: str, new_status: str, notes: Optional[str] = None) -> bool:
        allowed = {"PENDING_REVIEW", "APPROVED_CLEAN", "CONFIRMED_POISON"}
        if new_status not in allowed:
            raise ValueError(f"Invalid status: {new_status}. Allowed: {allowed}")
        
        now_str = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE quarantine_records
                SET status = ?, reviewed_at = ?, reviewer_notes = ?
                WHERE sample_id = ?
            """, (new_status, now_str, notes, sample_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_summary_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM quarantine_records")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT status, COUNT(*) FROM quarantine_records GROUP BY status")
            counts_by_status = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute("SELECT AVG(combined_score) FROM quarantine_records")
            avg_score = cursor.fetchone()[0] or 0.0

            return {
                "total_quarantined": total,
                "status_breakdown": counts_by_status,
                "avg_risk_score": round(avg_score, 4)
            }

    def export_to_dataframe(self) -> pd.DataFrame:
        records = self.get_records(limit=100000)
        if not records:
            return pd.DataFrame()
        flat_records = []
        for r in records:
            row = {
                "sample_id": r["sample_id"],
                "batch_id": r["batch_id"],
                "assigned_label": r["assigned_label"],
                "combined_score": r["combined_score"],
                "reason": r["reason"],
                "status": r["status"],
                "quarantined_at": r["quarantined_at"]
            }
            # Add features
            for k, v in r["features"].items():
                row[f"feat_{k}"] = v
            # Add layer scores
            for lk, lv in r["detector_scores"].items():
                row[f"score_{lk}"] = lv
            flat_records.append(row)
        return pd.DataFrame(flat_records)

if __name__ == "__main__":
    qs = QuarantineStore("data/test_quarantine.db")
    qs.add_record(
        sample_id="test_001",
        batch_id="b1",
        features={"f1": 1.23},
        assigned_label=0,
        combined_score=0.88,
        detector_scores={"layer_a": 0.85, "layer_b": 0.90},
        reason="Test anomaly"
    )
    print("Quarantine Stats:", qs.get_summary_stats())
