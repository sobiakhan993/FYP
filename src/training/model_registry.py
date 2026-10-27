"""
Model Registry & Instant Rollback Engine
BS Cybersecurity FYDP - Dawood University of Engineering & Technology

Complies with FR-09 & FR-10:
Maintains versioned model binaries and lineage metadata.
Promotes passing candidates to active production status and supports
instant rollback to prior approved versions if an operational issue occurs.
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import joblib
from src.common.logger import get_logger

logger = get_logger("ModelRegistry")

class ModelRegistry:
    def __init__(self, registry_dir: str = "models/registry"):
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.registry_dir / "registry_manifest.json"
        self._init_manifest()

    def _init_manifest(self) -> None:
        if not self.manifest_path.exists():
            manifest = {
                "active_version": None,
                "history": [],
                "versions": {}
            }
            self._save_manifest(manifest)

    def _load_manifest(self) -> Dict[str, Any]:
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_manifest(self, manifest: Dict[str, Any]) -> None:
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    def register_and_promote(
        self,
        model: Any,
        metrics: Dict[str, float],
        version_tag: Optional[str] = None,
        notes: str = "Promoted after passing Trusted Validation Gate"
    ) -> str:
        manifest = self._load_manifest()
        now_str = datetime.now(timezone.utc).isoformat()
        
        # Calculate new semantic version tag
        if not version_tag:
            current_active = manifest.get("active_version")
            if not current_active:
                version_tag = "v1.0.0"
            else:
                parts = current_active.lstrip("v").split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                version_tag = f"v{major}.{minor + 1}.0"

        model_filename = f"model_{version_tag}.joblib"
        model_path = self.registry_dir / model_filename
        joblib.dump(model, model_path)

        # Demote previous active version
        prev_active = manifest.get("active_version")
        if prev_active and prev_active in manifest["versions"]:
            manifest["versions"][prev_active]["status"] = "SUPERSEDED"

        manifest["versions"][version_tag] = {
            "version": version_tag,
            "filename": model_filename,
            "path": str(model_path),
            "promoted_at": now_str,
            "status": "ACTIVE",
            "validation_metrics": metrics,
            "notes": notes
        }
        manifest["active_version"] = version_tag
        manifest["history"].append({
            "action": "PROMOTE",
            "version": version_tag,
            "timestamp": now_str,
            "f1_score": metrics.get("f1_score")
        })

        self._save_manifest(manifest)
        logger.info(f"Model successfully promoted: {version_tag} (F1={metrics.get('f1_score', 0):.4f})")
        return version_tag

    def rollback(self, target_version: Optional[str] = None) -> Tuple[bool, str]:
        """
        Restores a previously approved model version as the active model.
        """
        manifest = self._load_manifest()
        current_active = manifest.get("active_version")
        
        if not target_version:
            # Pick the most recent superseded version
            candidates = [v for v, meta in manifest["versions"].items() if meta["status"] == "SUPERSEDED"]
            if not candidates:
                logger.warning("Rollback failed: No previous approved versions available.")
                return False, "No previous approved versions available for rollback"
            target_version = candidates[-1]

        if target_version not in manifest["versions"]:
            return False, f"Target version {target_version} does not exist in registry"

        target_file = self.registry_dir / manifest["versions"][target_version]["filename"]
        if not target_file.exists():
            return False, f"Model file for {target_version} not found on disk"

        now_str = datetime.now(timezone.utc).isoformat()
        if current_active:
            manifest["versions"][current_active]["status"] = "ROLLED_BACK"

        manifest["versions"][target_version]["status"] = "ACTIVE"
        manifest["active_version"] = target_version
        manifest["history"].append({
            "action": "ROLLBACK",
            "restored_version": target_version,
            "previous_version": current_active,
            "timestamp": now_str
        })

        self._save_manifest(manifest)
        logger.info(f"Model rolled back from {current_active} to {target_version}")
        return True, f"Successfully rolled back active model to {target_version}"

    def get_active_model(self) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        manifest = self._load_manifest()
        active_ver = manifest.get("active_version")
        if not active_ver or active_ver not in manifest["versions"]:
            return None, None
        
        meta = manifest["versions"][active_ver]
        model_path = self.registry_dir / meta["filename"]
        if not model_path.exists():
            return None, None
        
        model = joblib.load(model_path)
        return model, meta

    def get_registry_manifest(self) -> Dict[str, Any]:
        return self._load_manifest()

if __name__ == "__main__":
    reg = ModelRegistry("models/registry")
    from sklearn.ensemble import RandomForestClassifier
    m = RandomForestClassifier().fit([[1, 2], [3, 4]], [0, 1])
    v = reg.register_and_promote(m, {"f1_score": 0.96})
    print("Promoted version:", v)
    print("Manifest:", reg.get_registry_manifest())
