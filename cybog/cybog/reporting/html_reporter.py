"""
cybog/reporting/html_reporter.py — Self-contained HTML report (no external CDN).
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from typing import Optional
from cybog.state.assessment_state import AssessmentState
from cybog.models.finding import Severity
from cybog.reporting.report_model import ReportState


_SEV_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
    "unknown":  "#9ca3af",
}

_CSS = """
body{font-family:system-ui,sans-serif;margin:0;padding:0;background:#f8fafc;color:#1e293b}
header{background:#1e293b;color:#fff;padding:1.5rem 2rem}
header h1{margin:0;font-size:1.5rem}
header p{margin:.25rem 0 0;opacity:.7;font-size:.9rem}
main{max-width:1200px;margin:2rem auto;padding:0 1rem}
.card{background:#fff;border-radius:.5rem;box-shadow:0 1px 3px rgba(0,0,0,.1);padding:1.5rem;margin-bottom:1.5rem}
h2{font-size:1.1rem;margin:0 0 1rem;color:#334155}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem}
.stat{text-align:center;padding:1rem;background:#f1f5f9;border-radius:.5rem}
.stat .num{font-size:2rem;font-weight:700;color:#0f172a}
.stat .lbl{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{background:#f1f5f9;padding:.6rem .75rem;text-align:left;font-weight:600;color:#475569}
td{padding:.6rem .75rem;border-bottom:1px solid #e2e8f0;vertical-align:top;word-break:break-all}
tr:hover td{background:#f8fafc}
.badge{display:inline-block;padding:.2rem .6rem;border-radius:9999px;font-size:.7rem;font-weight:700;color:#fff}
.sev-critical{background:#dc2626} .sev-high{background:#ea580c}
.sev-medium{background:#d97706}   .sev-low{background:#2563eb}
.sev-info{background:#6b7280}    .sev-unknown{background:#9ca3af}
.status-COMPLETED{color:#16a34a;font-weight:600}
.status-FAILED{color:#dc2626;font-weight:600}
.status-SKIPPED{color:#94a3b8}
.status-RUNNING{color:#2563eb;font-weight:600}
.banner{padding:1rem 1.5rem;border-radius:.5rem;margin-bottom:1.5rem;font-weight:600;font-size:.95rem;border:1px solid}
.banner.warn{background:#fef2f2;color:#991b1b;border-color:#fca5a5}
.banner.warn h2{margin:0 0 .35rem;font-size:1.05rem}
.banner.ok{background:#ecfdf5;color:#166534;border-color:#86efac}
.banner.ok h2{margin:0 0 .35rem;font-size:1.05rem}
.badge-verified{background:#16a34a}
.badge-unverified{background:#dc2626}
"""


def _sev_badge(sev: str) -> str:
    return f'<span class="badge sev-{sev}">{sev.upper()}</span>'


def _status_cell(status: str) -> str:
    return f'<span class="status-{status}">{status}</span>'


class HTMLReporter:
    def generate(
        self,
        state: AssessmentState,
        output_dir: Path,
        version_state: Optional[ReportState] = None,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        html = self._build_html(state, version_state)
        path = output_dir / "report.html"
        path.write_text(html, encoding="utf-8")
        return path

    def _build_html(self, state: AssessmentState, version_state: Optional[ReportState] = None) -> str:
        a = state.assessment
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        findings = list(state.findings.values())
        targets = list(state.targets.values())
        jobs = list(state.jobs.values())

        sev_counts = state.finding_counts_by_severity()

        # --- Report state model (PRD S27-S32, S55-S58) ---
        if version_state is None:
            version_state = (
                ReportState.PRELIMINARY
                if state.has_pending_validation()
                else ReportState.VERIFIED
            )

        if version_state == ReportState.PRELIMINARY:
            banner = (
                '<div class="banner warn">'
                '<h2>\u26a0 UNVERIFIED \u2014 AUTOMATED ASSESSMENT</h2>'
                'Automated analysis identified potential security issues. '
                'These findings have not yet been manually verified and '
                'should not be treated as confirmed vulnerabilities.'
                '</div>'
            )
            badge = '<span class="badge badge-unverified">UNVERIFIED</span>'
        elif version_state == ReportState.VERIFIED:
            banner = (
                '<div class="banner ok">'
                '<h2>\u2713 VERIFIED</h2>'
                'These findings were manually verified by an authorized '
                'security analyst.'
                '</div>'
            )
            badge = '<span class="badge badge-verified">VERIFIED</span>'
        else:
            banner = ''
            badge = '<span class="badge badge-verified">' + version_state.value + '</span>'

        summary_stats = f"""
        <div class="grid">
            <div class="stat"><div class="num">{len(targets)}</div><div class="lbl">Targets</div></div>
            <div class="stat"><div class="num">{sum(len(v) for v in state.hosts.values())}</div><div class="lbl">Hosts</div></div>
            <div class="stat"><div class="num">{sum(len(v) for v in state.services.values())}</div><div class="lbl">Live Services</div></div>
            <div class="stat"><div class="num">{len(findings)}</div><div class="lbl">Findings</div></div>
            <div class="stat"><div class="num" style="color:#dc2626">{sev_counts.get('critical',0)}</div><div class="lbl">Critical</div></div>
            <div class="stat"><div class="num" style="color:#ea580c">{sev_counts.get('high',0)}</div><div class="lbl">High</div></div>
            <div class="stat"><div class="num" style="color:#d97706">{sev_counts.get('medium',0)}</div><div class="lbl">Medium</div></div>
            <div class="stat"><div class="num" style="color:#2563eb">{sev_counts.get('low',0)}</div><div class="lbl">Low</div></div>
        </div>"""

        # Targets table
        target_rows = "".join(
            f"<tr><td>{t.domain}</td><td>{t.target_id}</td>"
            f"<td>{_status_cell(t.status.value)}</td>"
            f"<td>{len(state.hosts.get(t.target_id, []))}</td>"
            f"<td>{len(state.services.get(t.target_id, []))}</td>"
            f"<td>{len([f for f in findings if f.target_id == t.target_id])}</td></tr>"
            for t in targets
        )
        targets_table = f"""
        <table><thead><tr>
            <th>Domain</th><th>Target ID</th><th>Status</th><th>Hosts</th><th>Services</th><th>Findings</th>
        </tr></thead><tbody>{target_rows}</tbody></table>"""

        # Findings table
        finding_rows = "".join(
            f"<tr><td>{_sev_badge(f.severity.value)}</td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.target_domain)}</td>"
            f"<td><a href='{_esc(f.url or '')}' target='_blank'>{_esc((f.url or '')[:60])}</a></td>"
            f"<td>{_esc(f.template_id or '')}</td>"
            f"<td>{_esc(f.validation_status.value)}</td>"
            f"<td>{f.occurrence_count}</td></tr>"
            for f in sorted(findings, key=lambda x: list(Severity).index(x.severity) if x.severity in list(Severity) else 99)
        )
        findings_table = f"""
        <table><thead><tr>
            <th>Severity</th><th>Title</th><th>Target</th><th>URL</th><th>Template</th><th>Status</th><th>Occurrences</th>
        </tr></thead><tbody>{finding_rows if finding_rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No findings</td></tr>'}</tbody></table>"""

        # Stage execution table
        job_rows = "".join(
            f"<tr><td>{_esc(j.target_domain)}</td>"
            f"<td>{_esc(j.stage)}</td>"
            f"<td>{_status_cell(j.status.value)}</td>"
            f"<td>{j.attempt}</td>"
            f"<td>{j.result_count}</td>"
            f"<td>{f'{j.duration_seconds:.1f}s' if j.duration_seconds else '—'}</td>"
            f"<td>{_esc((j.error or '')[:80])}</td></tr>"
            for j in sorted(jobs, key=lambda x: (x.target_domain, x.stage))
        )
        jobs_table = f"""
        <table><thead><tr>
            <th>Target</th><th>Stage</th><th>Status</th><th>Attempt</th><th>Results</th><th>Duration</th><th>Error</th>
        </tr></thead><tbody>{job_rows}</tbody></table>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cybog Assessment Report — {_esc(a.assessment_id)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>Cybog Security Assessment Report</h1>
  <p>Assessment: {_esc(a.assessment_id)} | Profile: {_esc(a.profile)} | Generated: {ts}</p>
  <p>Status: {_esc(a.status.value)} | Scope: {_esc(a.scope_file)}</p>
</header>
<main>
  {banner}
  <div class="card"><h2>Assessment Summary</h2>{summary_stats}<span style="float:right" class="badge">{badge}</span></div>
  <div class="card"><h2>Targets ({len(targets)})</h2>{targets_table}</div>
  <div class="card"><h2>Findings ({len(findings)})</h2>{findings_table}</div>
  <div class="card"><h2>Stage Execution ({len(jobs)} jobs)</h2>{jobs_table}</div>
</main>
</body>
</html>"""


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
