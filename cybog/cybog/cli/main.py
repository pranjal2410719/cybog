"""
cybog/cli/main.py

Full headless CLI for Project Cybog.
Commands: create, execute, status, findings, report, resume, cancel, tools, healthcheck

Business logic is in the service layer — CLI only handles I/O and calls services.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from cybog.config.loader import load_config
from cybog.logging_setup import setup_logging, get_logger
from cybog.models.assessment import Assessment, AssessmentStatus

app = typer.Typer(
    name="cybog",
    help="Cybog — Authorized Security Assessment Workflow Engine",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
console = Console()
err_console = Console(stderr=True, style="bold red")


# ─────────────────────────────────────────────
# cybog create
# ─────────────────────────────────────────────
@app.command("create")
def cmd_create(
    targets: str = typer.Option(..., "--targets", "-t", help="Path to targets .txt file"),
    scope: str = typer.Option(..., "--scope", "-s", help="Path to authorized_scope.txt"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Pipeline profile: standard|quick"),
    config_file: str = typer.Option("config.yaml", "--config", "-c", help="Config file path"),
    output_root: Optional[str] = typer.Option(None, "--output", help="Override output root dir"),
):
    """Create a new assessment. Validates scope and returns assessment_id."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    if output_root:
        cfg.output.root = output_root
    setup_logging(cfg.logging.level, cfg.logging.format)

    svc = AssessmentService(cfg)
    try:
        state = svc.create(targets_file=targets, scope_file=scope, profile=profile)
        console.print(f"\n[bold green]Assessment created:[/bold green]")
        console.print(f"  ID:      [cyan]{state.assessment.assessment_id}[/cyan]")
        console.print(f"  Profile: {state.assessment.profile}")
        console.print(f"  Targets: {targets}")
        console.print(f"  Scope:   {scope}")
        console.print(f"  Root:    {state.assessment.artifact_root}")
        console.print(f"\nRun: [bold]cybog execute {state.assessment.assessment_id}[/bold]\n")
    except Exception as exc:
        err_console.print(f"ERROR: {exc}")
        raise typer.Exit(1)


# ─────────────────────────────────────────────
# cybog execute
# ─────────────────────────────────────────────
@app.command("execute")
def cmd_execute(
    assessment_id: str = typer.Argument(..., help="Assessment ID to execute"),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Execute an assessment pipeline (runs all stages for all targets)."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    setup_logging(cfg.logging.level, cfg.logging.format)

    svc = AssessmentService(cfg)
    try:
        console.print(f"\n[bold blue]Executing assessment:[/bold blue] {assessment_id}")
        asyncio.run(svc.execute(assessment_id))
        console.print(f"\n[bold green]Assessment complete.[/bold green]")
        console.print(f"Run: [bold]cybog report {assessment_id}[/bold]\n")
    except Exception as exc:
        err_console.print(f"EXECUTION ERROR: {exc}")
        raise typer.Exit(1)


# ─────────────────────────────────────────────
# cybog status
# ─────────────────────────────────────────────
@app.command("status")
def cmd_status(
    assessment_id: str = typer.Argument(...),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Show assessment status: targets, jobs by status, stage distribution."""
    from cybog.services.assessment_service import AssessmentService
    from rich.progress import Progress
    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)

    a = Assessment(
        assessment_id="temp",
        profile="standard",
        target_input_file="",
        scope_file="",
        status=AssessmentStatus.CREATED,
    )
    state = svc.load_state(assessment_id)

    with Progress(
        console=console,
        transient=True,
        refresh_per_second=10,
    ) as progress:
        task = progress.add_task(
            "[cyan]Loading assessment state...[/cyan]", total=100
        )
        progress.update(task, completed=50)
        state = svc.load_state(assessment_id)
        progress.update(task, completed=100)

    console.print(f"\n[bold]Assessment:[/bold] {state.assessment.assessment_id}")
    console.print(
        f"Status: [bold]{state.assessment.status.value}[/bold]  Profile: {state.assessment.profile}"
    )
    console.print(
        f"Created: {state.assessment.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )

    # Target summary
    t = Table("Domain", "Status", "Hosts", "Services", "Findings", box=box.SIMPLE)
    for tgt in state.targets.values():
        fcount = len(state.get_findings_for_target(tgt.target_id))
        t.add_row(
            tgt.domain, tgt.status.value,
            str(len(state.hosts.get(tgt.target_id, []))),
            str(len(state.services.get(tgt.target_id, []))),
            str(fcount),
        )
    console.print(t)

    # Job status counts
    counts = state.job_counts_by_status()
    console.print("\n[bold]Jobs by status:[/bold]")
    for status, cnt in sorted(counts.items()):
        console.print(f"  {status:<12} {cnt}")

    console.print(f"\n[bold]Findings:[/bold] {len(state.findings)} unique")
    sev = state.finding_counts_by_severity()
    for s, c in sev.items():
        console.print(f"  {s:<10} {c}")
    console.print()


# ─────────────────────────────────────────────
# cybog findings
# ─────────────────────────────────────────────
@app.command("findings")
def cmd_findings(
    assessment_id: str = typer.Argument(...),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter: critical,high,medium,low,info"),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """List all findings with severity, title, target, URL, and validation status."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)
    state = svc.load_state(assessment_id)

    findings = list(state.findings.values())
    if severity:
        sev_filter = {s.strip().lower() for s in severity.split(",")}
        findings = [f for f in findings if f.severity.value in sev_filter]

    if not findings:
        console.print("[yellow]No findings found.[/yellow]")
        return

    t = Table("Sev", "Title", "Target", "URL", "Template", "Status", "×", box=box.SIMPLE)
    for f in sorted(findings, key=lambda x: x.severity.value):
        t.add_row(
            f.severity.value.upper(),
            f.title[:50],
            f.target_domain,
            (f.url or "")[:50],
            f.template_id or "",
            f.validation_status.value,
            str(f.occurrence_count),
        )
    console.print(t)
    console.print(f"\nTotal: {len(findings)} finding(s)\n")


# ─────────────────────────────────────────────
# cybog report
# ─────────────────────────────────────────────
@app.command("report")
def cmd_report(
    assessment_id: str = typer.Argument(...),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for running assessment to reach 100% before generating report"),
):
    """Generate JSON, JSONL, and HTML reports for an assessment."""
    import time
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from cybog.services.assessment_service import AssessmentService
    from cybog.reporting import JSONReporter, JSONLReporter, HTMLReporter
    from cybog.models.assessment import AssessmentStatus
    from cybog.models.job import JobStatus

    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)
    state = svc.load_state(assessment_id)

    # If the assessment is still active and user wants to wait
    if wait and state.assessment.status in (AssessmentStatus.RUNNING, AssessmentStatus.RESUMING, AssessmentStatus.CREATED):
        console.print(f"\n[bold yellow]Assessment {assessment_id} is currently {state.assessment.status.value}.[/bold yellow]")
        console.print("[dim]Waiting for all stages to reach 100% completion before generating final reports...[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total} jobs)"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Processing pipeline...", total=100)

            while True:
                state = svc.load_state(assessment_id)
                status = state.assessment.status

                total_jobs = len(state.jobs)
                finished_jobs = sum(
                    1 for j in state.jobs.values()
                    if j.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.SKIPPED, JobStatus.CANCELLED)
                )

                if total_jobs > 0:
                    pct = (finished_jobs / total_jobs) * 100
                    progress.update(task, completed=finished_jobs, total=total_jobs)
                else:
                    progress.update(task, completed=0, total=1)

                if status in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
                    progress.update(task, completed=total_jobs if total_jobs > 0 else 1, total=total_jobs if total_jobs > 0 else 1)
                    break

                time.sleep(2)

    output_dir = Path(cfg.output.root) / assessment_id / "aggregate"

    console.print(f"\n[bold blue]Generating reports...[/bold blue]")
    json_path = JSONReporter().generate(state, output_dir)
    jsonl_path = JSONLReporter().generate(state, output_dir)
    html_path = HTMLReporter().generate(state, output_dir)
    console.print(f"  JSON:  [cyan]{json_path}[/cyan]")
    console.print(f"  JSONL: [cyan]{jsonl_path}[/cyan]")
    console.print(f"  HTML:  [cyan]{html_path}[/cyan]\n")


# ─────────────────────────────────────────────
# cybog resume
# ─────────────────────────────────────────────
@app.command("resume")
def cmd_resume(
    assessment_id: str = typer.Argument(...),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Resume an interrupted assessment from where it left off."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    setup_logging(cfg.logging.level, cfg.logging.format)
    svc = AssessmentService(cfg)
    console.print(f"\n[bold blue]Resuming assessment:[/bold blue] {assessment_id}")
    try:
        asyncio.run(svc.resume(assessment_id))
        console.print(f"\n[bold green]Resume complete.[/bold green]\n")
    except Exception as exc:
        err_console.print(f"RESUME ERROR: {exc}")
        raise typer.Exit(1)


# ─────────────────────────────────────────────
# cybog cancel
# ─────────────────────────────────────────────
@app.command("cancel")
def cmd_cancel(
    assessment_id: str = typer.Argument(...),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Mark an assessment as CANCELLED."""
    from cybog.services.assessment_service import AssessmentService
    from cybog.models.assessment import AssessmentStatus
    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)
    state = svc.load_state(assessment_id)
    state.assessment.status = AssessmentStatus.CANCELLED
    svc.save_state(state)
    console.print(f"[yellow]Assessment {assessment_id} marked CANCELLED.[/yellow]")


# ─────────────────────────────────────────────
# cybog validate — human-assisted validation boundary
# ─────────────────────────────────────────────
@app.command("pending")
def cmd_pending(
    assessment_id: str = typer.Argument(...),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """List findings still awaiting a validation decision."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)
    pending = svc.pending_validation(assessment_id)
    if not pending:
        console.print("[green]No findings awaiting validation.[/green]")
        return
    console.print(
        f"[yellow]{len(pending)} finding(s) awaiting validation:[/yellow]"
    )
    for p in pending:
        console.print(
            f"  {p['dedup_key'][:12]}  {p['severity']:<8} "
            f"{p['validation_status']:<18} {p['title']}"
        )
        if p["url"]:
            console.print(f"      [dim]{p['url']}[/dim]")


@app.command("confirm")
def cmd_confirm(
    assessment_id: str = typer.Argument(...),
    dedup_key: str = typer.Argument(...),
    notes: str = typer.Option("", "--notes", "-n"),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Confirm a finding: VALIDATED -> REPORTABLE."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)
    if svc.confirm_finding(assessment_id, dedup_key, analyst_notes=notes or None):
        console.print(f"[green]Confirmed {dedup_key[:12]}[/green]")
    else:
        console.print(
            f"[red]Could not confirm {dedup_key[:12]}: "
            f"unknown finding or invalid transition[/red]"
        )
        raise typer.Exit(code=1)


@app.command("reject")
def cmd_reject(
    assessment_id: str = typer.Argument(...),
    dedup_key: str = typer.Argument(...),
    notes: str = typer.Option("", "--notes", "-n"),
    config_file: str = typer.Option("config.yaml", "--config", "-c"),
):
    """Reject a finding: VALIDATING -> FALSE_POSITIVE."""
    from cybog.services.assessment_service import AssessmentService
    cfg = _load_cfg(config_file)
    svc = AssessmentService(cfg)
    if svc.reject_finding(assessment_id, dedup_key, analyst_notes=notes or None):
        console.print(f"[yellow]Rejected {dedup_key[:12]} as false positive[/yellow]")
    else:
        console.print(
            f"[red]Could not reject {dedup_key[:12]}: "
            f"unknown finding or invalid transition[/red]"
        )
        raise typer.Exit(code=1)


# ─────────────────────────────────────────────
# cybog tools / healthcheck
# ─────────────────────────────────────────────
@app.command("tools")
def cmd_tools(config_file: str = typer.Option("config.yaml", "--config", "-c")):
    """Check availability and version of all configured tools."""
    _run_health_check(config_file)


@app.command("healthcheck")
def cmd_healthcheck(config_file: str = typer.Option("config.yaml", "--config", "-c")):
    """Full health check: tool binaries + config validation."""
    _run_health_check(config_file)


def _run_health_check(config_file: str) -> None:
    from cybog.adapters import (
        SubfinderAdapter, DnsxAdapter, HttpxAdapter, NaabuAdapter,
        KatanaAdapter, FfufAdapter, NucleiAdapter,
    )
    cfg = _load_cfg(config_file)
    adapters = [
        SubfinderAdapter(cfg.tools.subfinder),
        DnsxAdapter(cfg.tools.dnsx),
        HttpxAdapter(cfg.tools.httpx),
        NaabuAdapter(cfg.tools.naabu),
        KatanaAdapter(cfg.tools.katana),
        FfufAdapter(cfg.tools.ffuf),
        NucleiAdapter(cfg.tools.nuclei),
    ]
    t = Table("Tool", "Binary", "Available", "Version", "Error", box=box.SIMPLE)
    all_ok = True
    for adapter in adapters:
        hc = adapter.health_check()
        available = "[green]✔[/green]" if hc.available else "[red]✘[/red]"
        if not hc.available:
            all_ok = False
        t.add_row(
            hc.tool, hc.binary, available,
            hc.version or "—", hc.error or "—"
        )
    console.print(t)
    if all_ok:
        console.print("\n[bold green]All tools available.[/bold green]\n")
    else:
        console.print("\n[bold red]Some tools are missing. Install them before running.[/bold red]\n")


# ─────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────
def _load_cfg(config_file: str):
    try:
        return load_config(config_file)
    except Exception as exc:
        err_console.print(f"Config error: {exc}")
        raise typer.Exit(1)


def main():
    app()


if __name__ == "__main__":
    main()
