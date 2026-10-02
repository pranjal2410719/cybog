"""
cybog/queue/analyst_queue.py — Analyst Task Queue.

Bounded asyncio Queue for analyst validation tasks.
Each task references a finding and records the assessment/target it belongs to,
so a validation task can never act on a finding from another assessment.
Task records live in AssessmentState so validation work survives a restart.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AnalystTaskStatus(str, Enum):
    PENDING = "PENDING"            # queued, not yet picked up
    VALIDATING = "VALIDATING"      # a worker is resolving it
    AWAITING_ANALYST = "AWAITING_ANALYST"  # no automatic validator; needs a human
    COMPLETED = "COMPLETED"        # resolved to a terminal finding state


# Statuses a task is never re-executed from.
TERMINAL_TASK_STATUSES = frozenset({
    AnalystTaskStatus.COMPLETED,
    AnalystTaskStatus.AWAITING_ANALYST,
})


class AnalystTask(BaseModel):
    """
    A unit of validation work for exactly one finding.

    analysis_id/target_id are denormalized onto the task so the validation
    worker can verify isolation before touching the referenced finding.
    """

    task_id: str = Field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")
    assessment_id: str
    target_id: str
    finding_id: str
    analyst_id: str = "unassigned"
    status: AnalystTaskStatus = AnalystTaskStatus.PENDING
    description: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    result: Optional[str] = None

    def is_terminal(self) -> bool:
        return self.status in TERMINAL_TASK_STATUSES


class BoundedAnalystQueue:
    """Bounded queue for AnalystTask objects.

    When full, enqueue() blocks (backpressure to upstream producer). The queue
    is an in-memory transport only: the authoritative copy of every task lives
    in AssessmentState, so a restart rebuilds the queue from that record.
    """

    def __init__(self, name: str, max_size: int = 100):
        self.name = name
        self._queue: asyncio.Queue[Optional[AnalystTask]] = asyncio.Queue(maxsize=max_size)
        self._max_size = max_size
        self._enqueued_total: int = 0
        self._dequeued_total: int = 0

    async def enqueue(self, task: AnalystTask, timeout: Optional[float] = None) -> None:
        """Enqueue an analyst task. Blocks if queue is full (backpressure)."""
        if timeout is not None:
            await asyncio.wait_for(self._queue.put(task), timeout=timeout)
        else:
            await self._queue.put(task)
        self._enqueued_total += 1

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[AnalystTask]:
        """Dequeue an analyst task. Returns None on timeout or shutdown sentinel."""
        if timeout is not None:
            try:
                task = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                return None
        else:
            task = await self._queue.get()
        self._queue.task_done()
        self._dequeued_total += 1
        return task

    async def send_sentinel(self, count: int = 1) -> None:
        """Send N None sentinels to signal workers to shut down."""
        for _ in range(count):
            await self._queue.put(None)

    def size(self) -> int:
        return self._queue.qsize()

    def is_full(self) -> bool:
        return self._queue.full()

    def is_empty(self) -> bool:
        return self._queue.empty()

    @property
    def max_size(self) -> int:
        return self._max_size

    @property
    def stats(self) -> dict:
        return {
            "name": self.name,
            "current_size": self.size(),
            "max_size": self._max_size,
            "enqueued_total": self._enqueued_total,
            "dequeued_total": self._dequeued_total,
        }
