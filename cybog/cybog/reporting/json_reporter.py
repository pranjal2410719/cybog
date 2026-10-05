"""
cybog/reporting/json_reporter.py - JSON report generator.
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from cybog.state.assessment_state import AssessmentState
from cybog.reporting.report_model import ReportState


class JSONReporter:
    def generate(
        self,
        state: AssessmentState,
        output_dir: Path,
        version_state: Optional[ReportState] = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        report = self._build_report(state, version_state)
        path = output_dir / "report.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return path

    def _build_report(
        self,
        state: AssessmentState,
        version_state: Optional[ReportState] = None,
    ) -> dict:
        a = state.assessment
        report = {
            "assessment_id": a.assessment_id,
            "profile": a.profile,
            "status": a.status.value,
            "created_at": a.created_at.isoformat(),
            "started_at": a.started_at.isoformat() if a.started_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            "scope_file": a.scope_file,
            "target_input_file": a.target_input_file,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_targets": len(state.targets),
                "targets_by_status": self._count_by(state.targets.values(), "status"),
                "total_findings": len(state.findings),
                "findings_by_severity": state.finding_counts_by_severity(),
                "findings_by_validation_status": state.validation_counts(),
                "pending_validation": state.pending_validation_count(),
                "jobs_by_status": state.job_counts_by_status(),
                "total_hosts": sum(len(v) for v in state.hosts.values()),
                "total_services": sum(len(v) for v in state.services.values()),
                "total_ports": sum(len(v) for v in state.ports.values()),
                "total_endpoints": sum(len(v) for v in state.endpoints.values()),
            },
            "targets": [t.model_dump() for t in state.targets.values()],
            "hosts": {tid: [h.model_dump() for h in hosts]
                      for tid, hosts in state.hosts.items()},
            "services": {tid: [s.model_dump() for s in svcs]
                         for tid, svcs in state.services.items()},
            "ports": {tid: [p.model_dump() for p in ports]
                      for tid, ports in state.ports.items()},
            "findings": [f.model_dump() for f in state.findings.values()],
            "jobs": [j.model_dump() for j in state.jobs.values()],
            "artifacts": [art.model_dump() for art in state.artifacts.values()],
        }

        # --- Report state model (PRD S27-S32, S55-S58) ---
        if version_state is None:
            version_state = (
                ReportState.PRELIMINARY
                if state.has_pending_validation()
                else ReportState.VERIFIED
            )

        if version_state == ReportState.PRELIMINARY:
            report["report_state"] = "PRELIMINARY"
            report["disclaimer"] = (
                "Automated analysis identified potential security issues. "
                "These findings have not yet been manually verified and "
                "should not be treated as confirmed vulnerabilities."
            )
        elif version_state == ReportState.VERIFIED:
            report["report_state"] = "VERIFIED"
            report["disclaimer"] = (
                "These findings were manually verified by an authorized "
                "security analyst."
            )
        else:
            report["report_state"] = version_state.value

        return report

    @staticmethod
    def _count_by(items, attr: str) -> dict:
        counts: dict = {}
        for item in items:
            val = str(getattr(item, attr, "unknown"))
            counts[val] = counts.get(val, 0) + 1
        return counts
