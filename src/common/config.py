"""
Configuration loader for the Poisoning Defense Platform.
Loads data, stream, detectors, and experiments YAML specifications.
"""

import os
from pathlib import Path
from typing import Any, Dict
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CONFIGS_DIR = ROOT_DIR / "configs"

def load_yaml(file_name: str) -> Dict[str, Any]:
    file_path = CONFIGS_DIR / file_name
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_data_config() -> Dict[str, Any]:
    return load_yaml("data.yaml")

def get_stream_config() -> Dict[str, Any]:
    return load_yaml("stream.yaml")

def get_detectors_config() -> Dict[str, Any]:
    return load_yaml("detectors.yaml")

def get_experiments_config() -> Dict[str, Any]:
    return load_yaml("experiments.yaml")
