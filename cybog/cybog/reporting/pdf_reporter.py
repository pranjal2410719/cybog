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
        
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(path)
        except ImportError:
            logging.getLogger(__name__).warning("weasyprint not installed, falling back to dummy PDF")
            # Fallback for systems without weasyprint
            path.write_text(f"PDF Output Placeholder\n\nEnsure weasyprint is installed to generate real PDFs.\n\nOriginal HTML:\n{html_content}", encoding="utf-8")

        # Symlink/copy for backwards compatibility
        symlink_path = output_dir / "report.pdf"
        if symlink_path.exists():
            symlink_path.unlink()
        try:
            symlink_path.symlink_to(filename)
        except OSError:
            import shutil
            shutil.copy2(path, symlink_path)
            
        return path
