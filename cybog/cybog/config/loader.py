"""
cybog/config/loader.py — Load and validate config.yaml into CybogConfig.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import ValidationError

from cybog.config.models import CybogConfig

_config_cache: Optional[CybogConfig] = None

# Config keys whose values are filesystem paths. A relative value is resolved
# against the directory containing config.yaml, not the process working
# directory, so the same config file behaves identically whether the pipeline
# is launched from the CLI (cybog/) or from the API server (backend/).
_PATH_KEYS = (
    ("targets", "input"),
    ("authorization", "scope_file"),
    ("tools", "ffuf", "wordlist"),
    ("output", "root"),
)


def _resolve_relative_paths(raw: Any, base_dir: Path) -> Any:
    """Rewrite relative path values in ``raw`` so they are based at ``base_dir``."""
    if not isinstance(raw, dict):
        return raw

    for key_path in _PATH_KEYS:
        node: Any = raw
        for part in key_path[:-1]:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if not isinstance(node, dict):
            continue

        leaf = key_path[-1]
        value = node.get(leaf)
        if not isinstance(value, str) or not value.strip():
            continue

        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            node[leaf] = str((base_dir / candidate))
    return raw


def load_config(config_path: str | Path = "config.yaml") -> CybogConfig:
    """Load config.yaml. Raises ValueError on invalid config."""
    global _config_cache
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path.resolve()}")
    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}
    # Anchor relative paths at the config file's own directory so they do not
    # depend on the caller's working directory.
    raw = _resolve_relative_paths(raw, path.resolve().parent)
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
