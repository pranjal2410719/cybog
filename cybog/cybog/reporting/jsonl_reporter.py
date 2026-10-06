"""
cybog/reporting/jsonl_reporter.py — One finding per JSONL line.
"""
from __future__ import annotations
import json
from pathlib import Path
from cybog.state.assessment_state import AssessmentState


class JSONLReporter:
    def generate(self, state: AssessmentState, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        is_verified = not state.has_pending_validation()
        status_suffix = "verified" if is_verified else "unverified"
        filename = f"findings_{status_suffix}.jsonl"
        
        path = output_dir / filename
        lines = [
            json.dumps(f.model_dump(), default=str)
            for f in state.findings.values()
        ]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        
        # Keep a copy for backwards compatibility
        compat_path = output_dir / "findings.jsonl"
        if compat_path.exists() or compat_path.is_symlink():
            compat_path.unlink()
        
        import shutil
        shutil.copy2(path, compat_path)
            
        return path
