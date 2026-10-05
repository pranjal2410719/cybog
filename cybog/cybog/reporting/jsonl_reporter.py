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
        
        # Keep a symlink or copy for backwards compatibility
        symlink_path = output_dir / "findings.jsonl"
        if symlink_path.exists():
            symlink_path.unlink()
        try:
            symlink_path.symlink_to(filename)
        except OSError:
            symlink_path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            
        return path
