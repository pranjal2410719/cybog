"""
cybog/config/loader.py — Load and validate config.yaml into CybogConfig.
"""
from __future__ import annotations
from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from cybog.config.models import CybogConfig

_config_cache: Optional[CybogConfig] = None


def load_config(config_path: str | Path = "config.yaml") -> CybogConfig:
    """Load config.yaml. Raises ValueError on invalid config."""
    global _config_cache
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path.resolve()}")
    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}
    try:
        _config_cache = CybogConfig(**raw)
        return _config_cache
    except ValidationError as e:
        raise ValueError(f"Invalid config at {path}: {e}") from e


def get_config() -> CybogConfig:
    """Return cached config or raise if not loaded."""
    if _config_cache is None:
        raise RuntimeError("Config not loaded. Call load_config() first.")
    return _config_cache


def reset_config() -> None:
    global _config_cache
    _config_cache = None
