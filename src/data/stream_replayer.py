"""
Micro-batch Stream Replayer & Schema Validator
Emits timestamped micro-batches from network flow datasets to approximate a live cloud stream.
BS Cybersecurity FYDP - Dawood University of Engineering & Technology
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Generator, List, Dict, Any, Tuple
import pandas as pd
from src.common.config import get_stream_config, get_data_config
from src.common.logger import get_logger
from src.common.types import SampleRecord, BatchRecord

logger = get_logger("StreamReplayer")

class SchemaValidator:
    def __init__(self, expected_features: List[str]):
        self.expected_features = expected_features

    def validate_record(self, record: Dict[str, Any]) -> Tuple[bool, str]:
        # Check required fields
        for feature in self.expected_features:
            if feature not in record:
                return False, f"Missing required feature: {feature}"
            val = record[feature]
            if pd.isna(val) or val is None:
                return False, f"Null or NaN detected in feature: {feature}"
            if not isinstance(val, (int, float)):
                return False, f"Invalid numeric type for feature: {feature}"
        return True, "Valid"

class StreamReplayer:
    def __init__(self, data_path: str = None, batch_size: int = None, interval: float = None):
        stream_cfg = get_stream_config()["stream"]
        data_cfg = get_data_config()
        
        self.data_path = data_path or stream_cfg.get("source_file", "data/processed/val.csv")
        self.batch_size = batch_size or stream_cfg.get("batch_size", 100)
        self.interval = interval if interval is not None else stream_cfg.get("interval_seconds", 1.0)
        self.features = data_cfg["features"]["numerical"]
        self.target = data_cfg["features"]["target"]
        self.validator = SchemaValidator(self.features)

        logger.info(f"Loading stream replay dataset from: {self.data_path}")
        self.df = pd.read_csv(self.data_path)
        logger.info(f"Stream replayer ready with {len(self.df)} total records (Batch size: {self.batch_size})")

    def emit_micro_batches(self, max_batches: int = None) -> Generator[BatchRecord, None, None]:
        total_rows = len(self.df)
        num_batches = (total_rows + self.batch_size - 1) // self.batch_size
        if max_batches:
            num_batches = min(num_batches, max_batches)

        for batch_idx in range(num_batches):
            start_i = batch_idx * self.batch_size
            end_i = min(start_i + self.batch_size, total_rows)
            chunk = self.df.iloc[start_i:end_i]

            samples: List[SampleRecord] = []
            now_str = datetime.now(timezone.utc).isoformat()
            batch_id = f"batch_{batch_idx:04d}_{uuid.uuid4().hex[:8]}"

            for _, row in chunk.iterrows():
                row_dict = row.to_dict()
                is_valid, reason = self.validator.validate_record(row_dict)
                if not is_valid:
                    logger.warning(f"Discarding invalid stream record: {reason}")
                    continue

                feature_vals = {f: float(row_dict[f]) for f in self.features}
                sample_id = f"smpl_{uuid.uuid4().hex[:12]}"
                ground_truth = bool(row_dict.get("is_poisoned", False))

                samples.append(SampleRecord(
                    sample_id=sample_id,
                    timestamp=now_str,
                    features=feature_vals,
                    label=int(row_dict[self.target]),
                    source_id="cloud_network_replayer",
                    ground_truth_poisoned=ground_truth
                ))

            batch_record = BatchRecord(
                batch_id=batch_id,
                source="cloud_ids_stream_replayer",
                received_at=now_str,
                record_count=len(samples),
                samples=samples
            )

            logger.info(f"Emitted {batch_id} with {len(samples)} valid records")
            yield batch_record

            if self.interval > 0:
                time.sleep(self.interval)

if __name__ == "__main__":
    replayer = StreamReplayer(batch_size=50, interval=0.1)
    for b in replayer.emit_micro_batches(max_batches=2):
        print(f"Replayed Batch: {b.batch_id}, count={b.record_count}")
