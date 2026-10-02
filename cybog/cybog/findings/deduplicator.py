"""
cybog/findings/deduplicator.py

FindingDeduplicator — hash-keyed deduplication across all targets and tools.
Thread-safe via asyncio.Lock.
"""
from __future__ import annotations
import asyncio
from datetime import datetime
from cybog.models.finding import Finding


class FindingDeduplicator:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._registry: dict[str, Finding] = {}

    async def add(self, finding: Finding) -> bool:
        """
        Add a finding. Returns True if NEW, False if deduplicated.
        Increments occurrence_count and updates last_seen on duplicate.
        """
        async with self._lock:
            if finding.dedup_key in self._registry:
                existing = self._registry[finding.dedup_key]
                existing.occurrence_count += 1
                existing.last_seen = datetime.utcnow()
                return False
            self._registry[finding.dedup_key] = finding
            return True

    async def get_unique(self) -> list[Finding]:
        async with self._lock:
            return list(self._registry.values())

    async def count(self) -> int:
        async with self._lock:
            return len(self._registry)

    def add_sync(self, finding: Finding) -> bool:
        """Synchronous version for use outside async context."""
        if finding.dedup_key in self._registry:
            existing = self._registry[finding.dedup_key]
            existing.occurrence_count += 1
            existing.last_seen = datetime.utcnow()
            return False
        self._registry[finding.dedup_key] = finding
        return True

    def get_unique_sync(self) -> list[Finding]:
        return list(self._registry.values())
