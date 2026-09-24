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
        path = output_dir / "findings.jsonl"
        lines = [
            json.dumps(f.model_dump(), default=str)
            for f in state.findings.values()
        ]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path
