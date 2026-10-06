"""
cybog/reporting/pdf_reporter.py — Generates PDF reports from HTML.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import Optional

from cybog.state.assessment_state import AssessmentState
from cybog.reporting.report_model import ReportState
from cybog.reporting.html_reporter import HTMLReporter

class PDFReporter:
    def generate(
        self,
        state: AssessmentState,
        output_dir: Path,
        version_state: Optional[ReportState] = None,
        context: dict = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Build HTML content
        html_reporter = HTMLReporter()
        html_content = html_reporter._build_html(state, version_state, context)
        
        is_verified = (version_state == ReportState.VERIFIED) if version_state is not None else not state.has_pending_validation()
        status_suffix = "verified" if is_verified else "unverified"
        filename = f"report_{status_suffix}.pdf"
        path = output_dir / filename
        
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(path)

        # Keep a copy for backwards compatibility
        compat_path = output_dir / "report.pdf"
        if compat_path.exists() or compat_path.is_symlink():
            compat_path.unlink()
        
        import shutil
        shutil.copy2(path, compat_path)
            
        return path
