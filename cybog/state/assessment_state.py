"""
cybog/state/assessment_state.py

Single persistent AssessmentState — the source of truth.
All normalized entities live here. Raw output lives in artifacts.
Serializable to/from JSON. Supports atomic save for crash safety.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from cybog.models.assessment import Assessment, AssessmentStatus
from cybog.models.target import Target, Host, IP, Port, Service, URL, Endpoint
from cybog.models.finding import Finding
from cybog.models.job import StageJob, JobStatus
from cybog.models.artifact import Artifact


class AssessmentState(BaseModel):
    # ── Core assessment ────────────────────────────────────────────────
    assessment: Assessment

    # ── Targets ────────────────────────────────────────────────────────
    targets: dict[str, Target] = Field(default_factory=dict)  # target_id -> Target

    # ── Discovered assets ──────────────────────────────────────────────
    hosts: dict[str, list[Host]] = Field(default_factory=dict)       # target_id -> [Host]
    ips: dict[str, list[IP]] = Field(default_factory=dict)           # target_id -> [IP]
    ports: dict[str, list[Port]] = Field(default_factory=dict)       # target_id -> [Port]
    services: dict[str, list[Service]] = Field(default_factory=dict) # target_id -> [Service]
    urls: dict[str, list[URL]] = Field(default_factory=dict)         # target_id -> [URL]
    endpoints: dict[str, list[Endpoint]] = Field(default_factory=dict)

    # ── Findings ───────────────────────────────────────────────────────
    findings: dict[str, Finding] = Field(default_factory=dict)  # dedup_key -> Finding

    # ── Execution / job tracking ───────────────────────────────────────
    jobs: dict[str, StageJob] = Field(default_factory=dict)  # job_id -> StageJob

    # ── Artifacts ──────────────────────────────────────────────────────
    artifacts: dict[str, Artifact] = Field(default_factory=dict)  # artifact_id -> Artifact

    # ── Metadata ──────────────────────────────────────────────────────
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    # ------------------------------------------------------------------
    # Target helpers
    # ------------------------------------------------------------------
    def add_target(self, target: Target) -> None:
        self.targets[target.target_id] = target

    def get_target(self, target_id: str) -> Optional[Target]:
        return self.targets.get(target_id)

    def get_target_by_domain(self, domain: str) -> Optional[Target]:
        for t in self.targets.values():
            if t.domain == domain:
                return t
        return None

    # ------------------------------------------------------------------
    # Asset helpers
    # ------------------------------------------------------------------
    def add_hosts(self, target_id: str, hosts: list[Host]) -> None:
        existing = {h.hostname for h in self.hosts.get(target_id, [])}
        for h in hosts:
            if h.hostname not in existing:
                self.hosts.setdefault(target_id, []).append(h)
                existing.add(h.hostname)

    def add_ports(self, target_id: str, ports: list[Port]) -> None:
        existing = {(p.host, p.port) for p in self.ports.get(target_id, [])}
        for p in ports:
            key = (p.host, p.port)
            if key not in existing:
                self.ports.setdefault(target_id, []).append(p)
                existing.add(key)

    def add_services(self, target_id: str, services: list[Service]) -> None:
        existing = {s.url for s in self.services.get(target_id, [])}
        for s in services:
            if s.url not in existing:
                self.services.setdefault(target_id, []).append(s)
                existing.add(s.url)

    def add_urls(self, target_id: str, urls: list[URL]) -> None:
        existing = {u.url for u in self.urls.get(target_id, [])}
        for u in urls:
            if u.url not in existing:
                self.urls.setdefault(target_id, []).append(u)
                existing.add(u.url)

    def add_endpoints(self, target_id: str, endpoints: list[Endpoint]) -> None:
        existing = {e.url for e in self.endpoints.get(target_id, [])}
        for e in endpoints:
            if e.url not in existing:
                self.endpoints.setdefault(target_id, []).append(e)
                existing.add(e.url)

    def get_live_urls_for_target(self, target_id: str) -> list[str]:
        return [s.url for s in self.services.get(target_id, [])]

    def get_all_urls_for_target(self, target_id: str) -> list[str]:
        urls = set(self.get_live_urls_for_target(target_id))
        urls.update(u.url for u in self.urls.get(target_id, []))
        urls.update(e.url for e in self.endpoints.get(target_id, []))
        return list(urls)

    def get_resolved_hosts_for_target(self, target_id: str) -> list[str]:
        return [h.hostname for h in self.hosts.get(target_id, [])]

    # ------------------------------------------------------------------
    # Finding helpers
    # ------------------------------------------------------------------
    def add_finding(self, finding: Finding) -> bool:
        """Add finding. Returns True if new, False if deduplicated."""
        if finding.dedup_key in self.findings:
            existing = self.findings[finding.dedup_key]
            existing.occurrence_count += 1
            existing.last_seen = datetime.utcnow()
            return False
        self.findings[finding.dedup_key] = finding
        return True

    def get_findings_for_target(self, target_id: str) -> list[Finding]:
        return [f for f in self.findings.values() if f.target_id == target_id]

    # ------------------------------------------------------------------
    # Job helpers
    # ------------------------------------------------------------------
    def add_job(self, job: StageJob) -> None:
        self.jobs[job.job_id] = job

    def update_job(self, job: StageJob) -> None:
        self.jobs[job.job_id] = job

    def get_jobs_for_target(self, target_id: str) -> list[StageJob]:
        return [j for j in self.jobs.values() if j.target_id == target_id]

    def get_job_for_stage(self, target_id: str, stage: str) -> Optional[StageJob]:
        for j in self.jobs.values():
            if j.target_id == target_id and j.stage == stage:
                return j
        return None

    def is_stage_completed(self, target_id: str, stage: str) -> bool:
        job = self.get_job_for_stage(target_id, stage)
        return job is not None and job.status == JobStatus.COMPLETED

    def is_stage_failed(self, target_id: str, stage: str) -> bool:
        job = self.get_job_for_stage(target_id, stage)
        return job is not None and job.status == JobStatus.FAILED

    def get_incomplete_jobs(self) -> list[StageJob]:
        """Jobs that were RUNNING or PENDING at crash time — candidates for resume."""
        return [
            j for j in self.jobs.values()
            if j.status in (JobStatus.RUNNING, JobStatus.PENDING, JobStatus.READY)
        ]

    def get_failed_jobs(self) -> list[StageJob]:
        return [j for j in self.jobs.values() if j.status == JobStatus.FAILED]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def save(self, path: str | Path) -> None:
        """Atomic save: write to .tmp then rename to avoid corruption."""
        self.last_updated = datetime.utcnow()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(self.model_dump_json(indent=2))
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str | Path) -> "AssessmentState":
        """Load state from JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"State file not found: {path}")
        data = json.loads(path.read_text())
        return cls.model_validate(data)

    @classmethod
    def create_new(cls, assessment: Assessment) -> "AssessmentState":
        return cls(assessment=assessment)

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------
    def job_counts_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for j in self.jobs.values():
            counts[j.status.value] = counts.get(j.status.value, 0) + 1
        return counts

    def finding_counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings.values():
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
